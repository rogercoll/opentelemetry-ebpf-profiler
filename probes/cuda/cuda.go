// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package cuda attaches to the USDT probes ("gpuprofiling" provider) of a GPU
// profiling agent injected into CUDA processes.
//
// An OTel config using this probe could look like this:
//
//	receivers:
//	  profiling:
//	    probes:
//	      - cuda
//
//	extensions:
//	  cuda:
package cuda // import "go.opentelemetry.io/ebpf-profiler/probes/cuda"

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	"go.opentelemetry.io/ebpf-profiler/usdt"
)

const (
	// Collects the launch stack, value = correlation ID
	launchProgName = "kprobe__usdt_arg0"
	// Sends one kernel record to userspace
	kernelProgName  = "kprobe__cuda_kernel"
	kernelEventsMap = "cuda_kernel_events"
	// Agent library, matched by file name
	agentLibrary = "libcudaprofiling.so"
	usdtProvider = "gpuprofiling"
)

type Config struct{}

type probe struct {
	// Shared eBPF programs loaded once in Load, reused across Attach calls.
	launchProg *cebpf.Program
	kernelProg *cebpf.Program
	// events and reader carry kernel records from eBPF
	events     *cebpf.Map
	reader     *ringbuf.Reader
	discoverer *usdt.Discoverer
	// originID tags this probe's traces (registered in Load)
	originID uint16

	mu       sync.Mutex
	unloaded bool
	links    map[libpf.PID][]link.Link
}

func (p *probe) String() string {
	return "cuda"
}

func New(Config) (tracer.Probe, error) {
	d, err := usdt.NewDiscoverer()
	if err != nil {
		return nil, err
	}
	return &probe{
		discoverer: d,
		links:      make(map[libpf.PID][]link.Link),
	}, nil
}

// Load implements tracer.Probe. It loads the shared eBPF programs once and registers
// the probe as a per-process attacher so that SynchronizeProcess drives per-PID
// attachment rather than a single system-wide link.
func (p *probe) Load(_ context.Context, reg tracer.ProbeRegistrar, probeCtx *tracer.ProbeContext) error {
	originID, err := reg.Register(&samples.TypeMetadata{
		SampleType: "events",
		SampleUnit: "count",
	})
	if err != nil {
		return fmt.Errorf("registering probe origin: %w", err)
	}
	p.originID = originID

	coll, err := probeCtx.CollectionSpecWith(
		[]string{kernelEventsMap},
		[]string{launchProgName, kernelProgName},
		[]string{"origin_id_probe"},
	)
	if err != nil {
		return err
	}

	v, ok := coll.Variables["origin_id_probe"]
	if !ok {
		return fmt.Errorf("origin_id_probe variable not found in collection spec")
	}
	if err := v.Set(originID); err != nil {
		return err
	}

	p.events, err = cebpf.NewMap(coll.Maps[kernelEventsMap])
	if err != nil {
		return fmt.Errorf("creating %s: %w", kernelEventsMap, err)
	}
	if err := probeCtx.RewriteMaps(coll, map[string]*cebpf.Map{kernelEventsMap: p.events}); err != nil {
		return err
	}

	ebpfProgs := make(map[string]*cebpf.Program)
	if err := probeCtx.LoadProbeUnwinders(coll, ebpfProgs, []tracer.ProgLoaderHelper{
		{
			Name:             launchProgName,
			NoTailCallTarget: true,
			Enable:           true,
		},
		{
			Name:             kernelProgName,
			NoTailCallTarget: true,
			Enable:           true,
		},
	}, 0); err != nil {
		return err
	}

	for name, dst := range map[string]**cebpf.Program{
		launchProgName: &p.launchProg,
		kernelProgName: &p.kernelProg,
	} {
		prog, ok := ebpfProgs[name]
		if !ok {
			return fmt.Errorf("program %q not found after loading", name)
		}
		*dst = prog
	}

	p.reader, err = ringbuf.NewReader(p.events)
	if err != nil {
		return fmt.Errorf("reading %s: %w", kernelEventsMap, err)
	}
	go p.readKernelEvents()

	// Register for per-process callbacks instead of a global link.
	if err := probeCtx.AddAttacher(p); err != nil {
		_ = p.reader.Close()
		_ = p.events.Close()
		_ = p.launchProg.Close()
		_ = p.kernelProg.Close()
		return fmt.Errorf("registering process attacher: %w", err)
	}
	return nil
}

// Match implements processmanager.ProbeAttacher.
func (p *probe) Match(_ process.Process, mapping *process.RawMapping) bool {
	return filepath.Base(mapping.Path) == agentLibrary
}

// Attach implements processmanager.ProbeAttacher. Attaches the launch and
// kernel programs at the agent's USDTs for this process.
func (p *probe) Attach(pr process.Process, mapping *process.RawMapping) error {
	pid := pr.PID()
	mappingFile, err := pr.OpenMappingFile(mapping)
	if err != nil {
		return fmt.Errorf("%s: open mapping %s: %w", p, mapping.Path, err)
	}
	defer mappingFile.Close()

	fdFile, ok := mappingFile.(interface{ Fd() uintptr })
	if !ok {
		return fmt.Errorf("%s: mapping %s has no file descriptor", p, mapping.Path)
	}
	mappingPath := fmt.Sprintf("/proc/self/fd/%d", fdFile.Fd())

	// Discover USDT notes through the same fd (cached by file identity)
	ref := pfelf.NewReferenceWithOpenFunc(mapping.Path, nil, func() (*pfelf.File, error) {
		return pfelf.Open(mappingPath)
	})
	defer ref.Close()
	points, err := p.discoverer.Discover(ref, mapping.GetOnDiskFileIdentifier())
	if err != nil && len(points) == 0 {
		return fmt.Errorf("%s: discover USDT in %s: %w", p, mapping.Path, err)
	}

	ex, err := link.OpenExecutable(mappingPath)
	if err != nil {
		return fmt.Errorf("%s: open mapping %s: %w", p, mapping.Path, err)
	}

	for _, pt := range points {
		if pt.Provider != usdtProvider {
			continue
		}
		var prog *cebpf.Program
		switch pt.Name {
		case "launch":
			prog = p.launchProg
		case "kernel":
			prog = p.kernelProg
		default:
			continue
		}
		// Address is the USDT's file offset; no symbol lookup
		lnk, err := ex.Uprobe("", prog, &link.UprobeOptions{
			PID:     int(pid),
			Address: pt.Location,
		})
		if err != nil {
			return fmt.Errorf("%s: attach to PID %d: %w", p, pid, err)
		}

		p.mu.Lock()
		if p.unloaded {
			p.mu.Unlock()
			// closing link due to unloaded probe
			return lnk.Close()
		}
		p.links[pid] = append(p.links[pid], lnk)
		p.mu.Unlock()
	}
	return nil
}

// Detach implements processmanager.ProbeAttacher. Closes all uprobe links
// for the exiting process.
func (p *probe) Detach(pid libpf.PID) {
	p.mu.Lock()
	links := p.links[pid]
	delete(p.links, pid)
	p.mu.Unlock()

	for _, lnk := range links {
		lnk.Close()
	}
}

func (p *probe) Unload() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.unloaded = true
	var unloadErrs error
	for pid, pidLinks := range p.links {
		for _, lnk := range pidLinks {
			unloadErrs = errors.Join(unloadErrs, lnk.Close())
		}
		delete(p.links, pid)
	}
	// Ends readKernelEvents
	unloadErrs = errors.Join(unloadErrs, p.reader.Close(), p.events.Close())

	return unloadErrs
}

// PreOrigins implements tracer.PreTraceHandler.
func (p *probe) PreOrigins() []uint16 {
	return []uint16{p.originID}
}

// PreHandleTrace implements tracer.PreTraceHandler.
// TODO: temporary, logs the correlation ID read from the launch USDT to verify
// the argument read. The launch/kernel correlator replaces this.
func (p *probe) PreHandleTrace(trace *libpf.EbpfTrace) bool {
	log.Infof("cuda: launch pid=%d tid=%d correlation=%d", trace.PID, trace.TID, trace.Value)
	return true
}

// kernelEvent mirrors CudaKernelEvent in support/ebpf/cuda_usdt.ebpf.c
type kernelEvent struct {
	CorrelationID uint64
	Start         uint64
	End           uint64
	PID           uint32
	DeviceID      uint32
	StreamID      uint32
	_             uint32
	Name          [128]byte
}

// readKernelEvents logs kernel records until Unload closes the reader.
// TODO: temporary, verifies the kernel USDT; the correlator consumes these.
func (p *probe) readKernelEvents() {
	for {
		record, err := p.reader.Read()
		if errors.Is(err, ringbuf.ErrClosed) {
			return
		}
		if err != nil {
			log.Warnf("cuda: reading kernel event: %v", err)
			continue
		}
		var ev kernelEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
			log.Warnf("cuda: decoding kernel event: %v", err)
			continue
		}
		name, _, _ := bytes.Cut(ev.Name[:], []byte{0})
		log.Infof("cuda: kernel pid=%d correlation=%d duration=%dns device=%d stream=%d name=%s",
			ev.PID, ev.CorrelationID, ev.End-ev.Start, ev.DeviceID, ev.StreamID, name)
	}
}
