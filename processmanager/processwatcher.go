// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
)

// ProcessWatcher is implemented by components that need to observe process lifecycle events.
// OnNewMapping is called for each new executable mapping seen for a process.
// OnProcessExit is called exactly once when a tracked process exits.
type ProcessWatcher interface {
	// OnNewMapping is called for each new executable mapping seen for a PID.
	// It may be called multiple times for the same PID if the process has more
	// than one mapping. The mapping pointer is valid only for the duration of
	// the call; implementations that retain it must copy the value.
	OnNewMapping(pr process.Process, m *process.RawMapping) error

	// OnProcessExit is called when a tracked process exits.
	OnProcessExit(pid libpf.PID) error
}
