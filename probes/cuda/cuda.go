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
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	"go.opentelemetry.io/ebpf-profiler/usdt"
)

const (
	progName = "kprobe__generic"
	// Agent library, matched by file name
	agentLibrary = "libcudaprofiling.so"
	usdtProvider = "gpuprofiling"
)

type Config struct{}

type probe struct {
	// prog is the shared eBPF program loaded once in Load, reused across Attach calls.
	prog       *cebpf.Program
	discoverer *usdt.Discoverer

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

// Load implements tracer.Probe. It loads the shared eBPF program once and registers
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

	coll, err := probeCtx.CollectionSpecWith(
		nil,
		[]string{progName},
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

	if err := probeCtx.RewriteMaps(coll, nil); err != nil {
		return err
	}

	ebpfProgs := make(map[string]*cebpf.Program)
	if err := probeCtx.LoadProbeUnwinders(coll, ebpfProgs, []tracer.ProgLoaderHelper{
		{
			Name:             progName,
			NoTailCallTarget: true,
			Enable:           true,
		},
	}, 0); err != nil {
		return err
	}

	prog, ok := ebpfProgs[progName]
	if !ok {
		return fmt.Errorf("program %q not found after loading", progName)
	}
	p.prog = prog

	// Register for per-process callbacks instead of a global link.
	if err := probeCtx.AddAttacher(p); err != nil {
		_ = p.prog.Close()
		p.prog = nil
		return fmt.Errorf("registering process attacher: %w", err)
	}
	return nil
}

// Match implements processmanager.ProbeAttacher.
func (p *probe) Match(_ process.Process, mapping *process.RawMapping) bool {
	return filepath.Base(mapping.Path) == agentLibrary
}

// Attach implements processmanager.ProbeAttacher. Attaches the stack-collecting
// program at the agent's "launch" USDT for this process.
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
		if pt.Provider != usdtProvider || pt.Name != "launch" {
			continue
		}
		// Address is the USDT's file offset; no symbol lookup
		lnk, err := ex.Uprobe("", p.prog, &link.UprobeOptions{
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

	return unloadErrs
}
