// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"sync"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/process/processcontext"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// ProcessContextStore resolves and serves the OTel process context of tracked
// processes. It implements the ProcessWatcher listener interfaces: the context
// mapping is selected during the mapping pass, resolved from remote process
// memory at the end of each pass, invalidated on exec, and dropped on exit.
//
// It reads the process env vars needed for the resolution from a
// MetadataStore, so that store must be registered before this one.
type ProcessContextStore struct {
	mu        sync.RWMutex
	metaStore *MetadataStore
	contexts  map[libpf.PID]processcontext.Info
}

// NewProcessContextStore returns a ProcessContextStore reading env-var derived
// attributes from metaStore.
func NewProcessContextStore(metaStore *MetadataStore) *ProcessContextStore {
	return &ProcessContextStore{
		metaStore: metaStore,
		contexts:  make(map[libpf.PID]processcontext.Info),
	}
}

func (s *ProcessContextStore) OnMappingsSync(pr process.Process,
	mappings []process.RawMapping) {
	pid := pr.PID()

	// 0 means no context mapping is present; Resolve then only derives
	// attributes from the process env vars.
	var contextMappingAddr uint64
	for i := range mappings {
		m := &mappings[i]
		if processcontext.IsContextMapping(m.IsExecutable(), m.Path) {
			contextMappingAddr = m.Vaddr
			break
		}
	}

	s.mu.RLock()
	oldContext := s.contexts[pid]
	s.mu.RUnlock()

	envVars := s.metaStore.MetaForPID(pid).InternalEnvVariables
	newContext := processcontext.Resolve(
		contextMappingAddr, pid, pr.GetRemoteMemory(), oldContext, envVars)

	s.mu.Lock()
	s.contexts[pid] = newContext
	s.mu.Unlock()
}

// OnProcessExec drops the stored context: an exec replaces the process image,
// so the previous context no longer applies.
func (s *ProcessContextStore) OnProcessExec(pr process.Process) {
	s.mu.Lock()
	delete(s.contexts, pr.PID())
	s.mu.Unlock()
}

func (s *ProcessContextStore) OnProcessExit(pid libpf.PID) {
	s.mu.Lock()
	delete(s.contexts, pid)
	s.mu.Unlock()
}

// DecorateTrace annotates meta with the resolved process-context resource
// attributes of the process the trace was captured from.
func (s *ProcessContextStore) DecorateTrace(_ *libpf.Trace, meta *samples.TraceEventMeta) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	meta.ResourceAttrs = s.contexts[meta.PID].ResourceAttrs
}
