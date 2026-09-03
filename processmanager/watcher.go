// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import "go.opentelemetry.io/ebpf-profiler/processmanager/processwatcher"

// notifyWatchers calls fn on every watcher implementing the listener
// interface T. Must be called without pm.mu held.
func notifyWatchers[T any](watchers []processwatcher.ProcessWatcher, fn func(T)) {
	for _, w := range watchers {
		if l, ok := w.(T); ok {
			fn(l)
		}
	}
}
