// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"sync"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// MetadataStore collects process.Meta at process discovery time and serves it
// on demand. It implements the ProcessWatcher listener interfaces and owns its
// own lock, independent of ProcessManager's.
type MetadataStore struct {
	mu        sync.RWMutex
	enrichers []process.MetaEnricher
	metas     map[libpf.PID]process.Meta
}

// NewMetadataStore returns a MetadataStore running the given enrichers at
// process discovery and exec time.
func NewMetadataStore(enrichers []process.MetaEnricher) *MetadataStore {
	return &MetadataStore{
		enrichers: enrichers,
		metas:     make(map[libpf.PID]process.Meta),
	}
}

func (s *MetadataStore) OnProcessNew(pr process.Process) {
	s.collect(pr)
}

func (s *MetadataStore) OnProcessExec(pr process.Process) {
	s.collect(pr)
}

func (s *MetadataStore) OnProcessExit(pid libpf.PID) {
	s.mu.Lock()
	delete(s.metas, pid)
	s.mu.Unlock()
}

// MetaForPID returns the stored metadata for pid, or a zero Meta if the
// process is not tracked.
func (s *MetadataStore) MetaForPID(pid libpf.PID) process.Meta {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.metas[pid]
}

// DecorateTrace annotates meta with the stored process metadata of the
// process the trace was captured from.
func (s *MetadataStore) DecorateTrace(_ *libpf.Trace, meta *samples.TraceEventMeta) {
	procMeta := s.MetaForPID(meta.PID)
	meta.ExecutablePath = procMeta.Executable
	meta.ContainerID = procMeta.ContainerID
	meta.EnvVars = procMeta.EnvVariables
	meta.ExtraMeta = procMeta.ExtraMeta
}

func (s *MetadataStore) collect(pr process.Process) {
	// Gather metadata without holding the lock: this reads /proc and may
	// invoke arbitrary enricher callbacks.
	meta := pr.GetProcessMeta(s.enrichers)
	s.mu.Lock()
	s.metas[pr.PID()] = meta
	s.mu.Unlock()
}
