// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package uprobe implements a per-process probe that attaches a PID-filtered uprobe
// to every process that maps a given target executable or shared library.
//
// An OTel config using this approach could look like this:
//
//	receivers:
//	  ebpf_profiler:
//	    probes:
//	      - uprobe/malloc
//
//	extensions:
//	  uprobe/malloc:
//	    target: /usr/lib/x86_64-linux-gnu/libc.so.6
//	    symbol: malloc
package uprobe // import "go.opentelemetry.io/ebpf-profiler/probes/uprobe"

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

const progName = "kprobe__generic"

type Config struct {
	Target string `mapstructure:"target"`
	Symbol string `mapstructure:"symbol"`
}

// Validate implements confmap.Validator.
func (c *Config) Validate() error {
	if c.Target == "" {
		return fmt.Errorf("uprobe: missing target")
	}
	if c.Symbol == "" {
		return fmt.Errorf("uprobe: missing symbol")
	}
	return nil
}

type probe struct {
	target string
	symbol string

	// prog is the shared eBPF program loaded once in Load, reused across attach calls.
	prog *cebpf.Program

	mu       sync.Mutex
	unloaded bool
	links    map[libpf.PID][]link.Link
	// seen tracks the mapping start addresses already offered per PID, so a
	// mapping is attached once even though every synchronization pass
	// delivers all mappings.
	seen map[libpf.PID]libpf.Set[uint64]
}

func (p *probe) String() string {
	return "uprobe " + p.target + ":" + p.symbol
}

func New(cfg Config) (tracer.Probe, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &probe{
		target: cfg.Target,
		symbol: cfg.Symbol,
		links:  make(map[libpf.PID][]link.Link),
		seen:   make(map[libpf.PID]libpf.Set[uint64]),
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
	p.mu.Lock()
	p.prog = prog
	p.mu.Unlock()

	return nil
}

// match reports whether the mapping belongs to the configured target.
func (p *probe) match(mapping *process.RawMapping) bool {
	return mapping.Path == p.target ||
		filepath.Base(mapping.Path) == filepath.Base(p.target)
}

// OnMappingsSync implements processmanager.MappingsListener. It opens a
// PID-restricted uprobe for every new mapping of the target executable and
// stores the link for later cleanup.
func (p *probe) OnMappingsSync(pr process.Process, mappings []process.RawMapping) {
	pid := pr.PID()

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.prog == nil || p.unloaded {
		// The probe is registered as a watcher at configuration time but its
		// eBPF program only loads when the probe is enabled. Don't mark
		// mappings as seen, so they attach on the next synchronization.
		return
	}
	prevSeen := p.seen[pid]
	seen := make(libpf.Set[uint64], len(prevSeen))
	for i := range mappings {
		m := &mappings[i]
		if !m.IsExecutable() || m.IsAnonymous() || !p.match(m) {
			continue
		}
		seen[m.Vaddr] = libpf.Void{}
		if _, ok := prevSeen[m.Vaddr]; ok {
			continue
		}
		if err := p.attach(pr, m); err != nil {
			log.Errorf("Failed to attach %s for PID %d: %v", p, pid, err)
		}
	}
	if len(seen) > 0 {
		p.seen[pid] = seen
	} else {
		delete(p.seen, pid)
	}
}

// attach opens a PID-restricted uprobe on the mapping's backing file.
// Caller must hold p.mu.
func (p *probe) attach(pr process.Process, mapping *process.RawMapping) error {
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

	ex, err := link.OpenExecutable(mappingPath)
	if err != nil {
		return fmt.Errorf("%s: open mapping %s: %w", p, mapping.Path, err)
	}

	lnk, err := ex.Uprobe(p.symbol, p.prog, &link.UprobeOptions{PID: int(pid)})
	if err != nil {
		return fmt.Errorf("%s: attach to PID %d: %w", p, pid, err)
	}

	if p.unloaded {
		// closing link due to unloaded probe
		return lnk.Close()
	}
	p.links[pid] = append(p.links[pid], lnk)
	return nil
}

// OnProcessExit implements processmanager.ProcessExitListener. Closes all
// uprobe links for the exiting process.
func (p *probe) OnProcessExit(pid libpf.PID) {
	p.mu.Lock()
	links := p.links[pid]
	delete(p.links, pid)
	delete(p.seen, pid)
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
			err := lnk.Close()
			if err != nil {
				unloadErrs = errors.Join(unloadErrs, err)
			}
		}
		delete(p.links, pid)
	}
	clear(p.seen)

	return unloadErrs
}
