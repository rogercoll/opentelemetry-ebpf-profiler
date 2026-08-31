// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
)

// ProcessEvent represents the type of eBPF probe.
type ProcessEvent int

const (
	// ProbeModeKprobe represents a kernel probe.
	NewMappingFrame ProcessEvent = iota
	// ProbeModeKretprobe represents a kernel return probe.
	Exited
)

// ConfigSnapshotWatcher is an interface that should be implemented by an
// extension that wishes to be notified of the Collector's configuration.
type ProcessSnapshotWatcher interface {
	// NotifyConfig notifies the extension of the Collector's current effective configuration.
	// The extension owns the `confmap.Conf`. Callers must ensure that it's safe for
	// extensions to store the `conf` pointer and use it concurrently with any other
	// instances of `conf`.
	NotifyProcess(event ProcessEvent, pid libpf.PID, snapShot ProcessSnapshot) error
}

// ProcessSnapshot provides access to different representations of the Collector's
// configuration.
type ProcessSnapshot interface {
	Process() process.Process
	Mapping() *process.RawMapping

	unexportedProcessSnapshot()
}

type processSnapshot struct {
	process process.Process
	mapping *process.RawMapping
}

func newProcessSnapshot(process process.Process, mapping *process.RawMapping) processSnapshot {
	return processSnapshot{
		process: process,
		mapping: mapping,
	}
}

func (ps processSnapshot) unexportedProcessSnapshot() {}

func (ps processSnapshot) Process() process.Process {
	// TODO: clone
	return ps.process
}

func (ps processSnapshot) Mapping() *process.RawMapping {
	// TODO: clone
	return ps.mapping
}
