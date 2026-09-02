// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
)

// ProcessWatcher is a consumer of process lifecycle events, provided via
// Config.ProcessWatchers. Implementations must also implement at least one of
// the listener interfaces below; ProcessManager type-asserts the watcher at
// each event, so a watcher is only invoked for the events it listens to.
//
// All listener methods are invoked without the ProcessManager's internal lock
// held, so watchers may call back into ProcessManager. Events for the same PID
// are delivered in order; events for different PIDs may be delivered
// concurrently.
type ProcessWatcher any

// ProcessNewListener is notified the first time a PID is observed.
type ProcessNewListener interface {
	// OnProcessNew is called synchronously while the process is still alive.
	// pr is only valid for the duration of the call and must not be retained,
	// with the exception of the reader returned by pr.GetRemoteMemory().
	OnProcessNew(pr process.Process)
}

// ProcessExecListener is notified when a tracked PID replaces its process
// image. Watchers should drop any state derived from the old image; the
// events that follow describe the new one.
type ProcessExecListener interface {
	// OnProcessExec is called synchronously; the same pr validity rules as
	// OnProcessNew apply.
	OnProcessExec(pr process.Process)
}

// ProcessExitListener is notified when a tracked process is removed.
type ProcessExitListener interface {
	// OnProcessExit is called after the process exited and all its pending
	// traces have been handled.
	OnProcessExit(pid libpf.PID)
}

// MappingsListener is notified at the end of every process synchronization
// pass with the process mappings observed during the pass.
type MappingsListener interface {
	// OnMappingsSync is called at the end of each synchronization pass with
	// all mappings of the process. The mappings are self-contained copies
	// with interned paths and are safe to store. The same pr validity rules
	// as OnProcessNew apply.
	OnMappingsSync(pr process.Process, mappings []process.RawMapping)
}

// notifyWatchers calls fn on every watcher implementing the listener
// interface T. Must be called without pm.mu held.
func notifyWatchers[T any](watchers []ProcessWatcher, fn func(T)) {
	for _, w := range watchers {
		if l, ok := w.(T); ok {
			fn(l)
		}
	}
}
