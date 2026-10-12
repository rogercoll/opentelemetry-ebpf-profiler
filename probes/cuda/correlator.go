// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package cuda // import "go.opentelemetry.io/ebpf-profiler/probes/cuda"

import (
	"sync"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

// key identifies one launch: correlation IDs are unique per process
type key struct {
	pid           libpf.PID
	correlationID uint64
}

// correlator joins launch traces with kernel records. The two arrive through
// different pipelines in either order, so whichever comes first waits.
//
// TODO: entries whose other half never arrives (a kernel launched before the
// profiler attached, a lost event) stay until the process exits.
// TODO: CUDA graphs: one launch yields many kernel records; only the first is
// joined.
type correlator struct {
	mu       sync.Mutex
	launches map[key]*libpf.EbpfTrace
	kernels  map[key]kernelEvent
	// report emits a held launch trace (ProbeContext.ReportTrace)
	report func(*libpf.EbpfTrace)
}

func newCorrelator(report func(*libpf.EbpfTrace)) *correlator {
	return &correlator{
		launches: make(map[key]*libpf.EbpfTrace),
		kernels:  make(map[key]kernelEvent),
		report:   report,
	}
}

// onLaunch handles a launch trace (value = correlation ID). Returns true if
// the trace was completed and continues to reporting, false if it is held.
func (c *correlator) onLaunch(trace *libpf.EbpfTrace) bool {
	k := key{trace.PID, uint64(trace.Value)}
	c.mu.Lock()
	ev, ok := c.kernels[k]
	if ok {
		delete(c.kernels, k)
	} else {
		c.launches[k] = copyTrace(trace)
	}
	c.mu.Unlock()

	if ok {
		applyKernel(trace, ev)
	}
	return ok
}

// onKernel handles a kernel record, reporting its launch if it is waiting.
func (c *correlator) onKernel(ev kernelEvent) {
	k := key{libpf.PID(ev.PID), ev.CorrelationID}
	c.mu.Lock()
	trace, ok := c.launches[k]
	if ok {
		delete(c.launches, k)
	} else {
		c.kernels[k] = ev
	}
	c.mu.Unlock()

	if ok {
		applyKernel(trace, ev)
		c.report(trace)
	}
}

// forget drops everything pending for an exited process.
func (c *correlator) forget(pid libpf.PID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.launches {
		if k.pid == pid {
			delete(c.launches, k)
		}
	}
	for k := range c.kernels {
		if k.pid == pid {
			delete(c.kernels, k)
		}
	}
}

// applyKernel turns a launch trace into a GPU time sample.
func applyKernel(trace *libpf.EbpfTrace, ev kernelEvent) {
	trace.Value = int64(ev.End - ev.Start)
	// CLOCK_MONOTONIC (agent timestamp callback), same clock as KTime
	trace.KTime = int64(ev.Start)
}

// copyTrace copies a pooled trace so it can be held after PreHandleTrace.
func copyTrace(trace *libpf.EbpfTrace) *libpf.EbpfTrace {
	held := new(libpf.EbpfTrace)
	*held = *trace
	// FrameData points into the original's buffer
	held.FrameData = held.FrameDataBuf[:len(trace.FrameData)]
	return held
}
