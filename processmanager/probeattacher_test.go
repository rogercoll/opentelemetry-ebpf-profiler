// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/times"
)

type recordingProbeAttacher struct {
	matchedMapping  *process.RawMapping
	attachedMapping *process.RawMapping
}

func (a *recordingProbeAttacher) Match(_ process.Process, mapping *process.RawMapping) bool {
	a.matchedMapping = mapping
	return true
}

func (a *recordingProbeAttacher) Attach(_ process.Process, mapping *process.RawMapping) error {
	a.attachedMapping = mapping
	return nil
}

func (*recordingProbeAttacher) Detach(libpf.PID) {}

// TestAttachProbesForMappingForwardsMatchedMapping verifies that Attach receives
// the exact mapping accepted by Match. Per-mapping probes need this to resolve
// symbol offsets and attach against the same backing ELF.
func TestAttachProbesForMappingForwardsMatchedMapping(t *testing.T) {
	attacher := &recordingProbeAttacher{}
	pm := &ProcessManager{
		probeAttachers: []ProbeAttacher{attacher},
		attachedProbes: make(map[libpf.PID]map[ProbeAttacher]libpf.Void),
	}
	pr := &testProcess{pid: 123}
	mapping := &process.RawMapping{
		Vaddr:  0x1000,
		Length: 0x2000,
		Path:   "/usr/lib/libc.so.6",
	}

	pm.attachProbesForMapping(pm.probeAttachers, pr, mapping)

	require.Same(t, attacher.matchedMapping, attacher.attachedMapping)
	require.Contains(t, pm.attachedProbes[pr.pid], attacher)
}

// pmLockTakingAttacher acquires pm.mu in every callback. It would deadlock if
// ProcessManager dispatched the callbacks with the lock held.
type pmLockTakingAttacher struct {
	pm       *ProcessManager
	attached bool
	detached bool
}

func (a *pmLockTakingAttacher) Match(process.Process, *process.RawMapping) bool {
	return true
}

func (a *pmLockTakingAttacher) Attach(process.Process, *process.RawMapping) error {
	a.pm.mu.Lock()
	a.attached = true
	a.pm.mu.Unlock()
	return nil
}

func (a *pmLockTakingAttacher) Detach(libpf.PID) {
	a.pm.mu.Lock()
	a.detached = true
	a.pm.mu.Unlock()
}

// TestProbeCallbacksDispatchedUnlocked verifies Attach and Detach are invoked
// without pm.mu held, so attachers may safely call back into ProcessManager.
func TestProbeCallbacksDispatchedUnlocked(t *testing.T) {
	pm := &ProcessManager{
		ebpf:             &testEbpfHandler{},
		pidToProcessInfo: map[libpf.PID]*processInfo{},
		exitEvents:       map[libpf.PID]times.KTime{},
		attachedProbes:   make(map[libpf.PID]map[ProbeAttacher]libpf.Void),
	}
	attacher := &pmLockTakingAttacher{pm: pm}
	pm.probeAttachers = []ProbeAttacher{attacher}

	pr := &testProcess{pid: 42}
	mapping := &process.RawMapping{Vaddr: 0x1000, Length: 0x1000, Path: "/bin/test"}

	pm.attachProbesForMapping(pm.probeAttachers, pr, mapping)
	require.True(t, attacher.attached)

	pm.pidToProcessInfo[pr.pid] = &processInfo{}
	pm.processPIDExit(pr.pid)
	require.True(t, attacher.detached)
}
