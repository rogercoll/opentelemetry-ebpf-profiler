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

// MetadataStore collects per-process metadata and serves it on demand: the
// process.Meta gathered at discovery and exec time, and the OTel process
// context resolved from remote process memory at every mapping
// synchronization. It implements the ProcessWatcher listener interfaces and
// owns its own lock, independent of ProcessManager's.
type MetadataStore struct {
	mu        sync.RWMutex
	enrichers []process.MetaEnricher
	metas     map[libpf.PID]process.Meta
	contexts  map[libpf.PID]processcontext.Info
}

// NewMetadataStore returns a MetadataStore running the given enrichers at
// process discovery and exec time.
func NewMetadataStore(enrichers []process.MetaEnricher) *MetadataStore {
	return &MetadataStore{
		enrichers: enrichers,
		metas:     make(map[libpf.PID]process.Meta),
		contexts:  make(map[libpf.PID]processcontext.Info),
	}
}

func (s *MetadataStore) OnProcessNew(pr process.Process) {
	s.collect(pr)
}

// OnProcessExec re-collects the process metadata and drops the stored
// process context: an exec replaces the image, so the previous context no
// longer applies.
func (s *MetadataStore) OnProcessExec(pr process.Process) {
	s.mu.Lock()
	delete(s.contexts, pr.PID())
	s.mu.Unlock()
	s.collect(pr)
}

// OnMappingsSync resolves the OTel process context from the process memory.
func (s *MetadataStore) OnMappingsSync(pr process.Process,
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
	envVars := s.metas[pid].InternalEnvVariables
	s.mu.RUnlock()

	newContext := processcontext.Resolve(
		contextMappingAddr, pid, pr.GetRemoteMemory(), oldContext, envVars)

	s.mu.Lock()
	s.contexts[pid] = newContext
	s.mu.Unlock()
}

func (s *MetadataStore) OnProcessExit(pid libpf.PID) {
	s.mu.Lock()
	delete(s.metas, pid)
	delete(s.contexts, pid)
	s.mu.Unlock()
}

// MetaForPID returns the stored metadata for pid, or a zero Meta if the
// process is not tracked.
func (s *MetadataStore) MetaForPID(pid libpf.PID) process.Meta {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.metas[pid]
}

// DecorateTrace annotates meta with the stored process metadata and the
// resolved process-context resource attributes of the process the trace was
// captured from.
func (s *MetadataStore) DecorateTrace(_ *libpf.Trace, meta *samples.TraceEventMeta) {
	s.mu.RLock()
	procMeta := s.metas[meta.PID]
	resourceAttrs := s.contexts[meta.PID].ResourceAttrs
	s.mu.RUnlock()

	meta.ExecutablePath = procMeta.Executable
	meta.ContainerID = procMeta.ContainerID
	meta.EnvVars = procMeta.EnvVariables
	meta.ExtraMeta = procMeta.ExtraMeta
	meta.ResourceAttrs = resourceAttrs
}

func (s *MetadataStore) collect(pr process.Process) {
	// Gather metadata without holding the lock: this reads /proc and may
	// invoke arbitrary enricher callbacks.
	meta := pr.GetProcessMeta(s.enrichers)
	s.mu.Lock()
	s.metas[pr.PID()] = meta
	s.mu.Unlock()
}
