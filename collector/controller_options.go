// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package collector // import "go.opentelemetry.io/ebpf-profiler/collector"

import (
	"go.opentelemetry.io/collector/consumer/xconsumer"

	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/processmanager/processwatcher"
	"go.opentelemetry.io/ebpf-profiler/reporter"
)

type Option interface {
	apply(*controllerOption) *controllerOption
}

type controllerOption struct {
	processMetaEnrichers []process.MetaEnricher
	processWatchers      []processwatcher.ProcessWatcher
	reporterFactory      func(cfg *reporter.Config, nextConsumer xconsumer.Profiles) (reporter.Reporter, error)
	onShutdown           func() error
}

type optFunc func(*controllerOption) *controllerOption

func (f optFunc) apply(c *controllerOption) *controllerOption { return f(c) }

// WithProcessWatcher registers watchers receiving process lifecycle events
// from the process manager. A watcher implements one or more of the
// processmanager listener interfaces (e.g. reporting seen executables from
// the mapping synchronization events).
func WithProcessWatcher(watchers ...processwatcher.ProcessWatcher) Option {
	return optFunc(func(option *controllerOption) *controllerOption {
		option.processWatchers = append(option.processWatchers, watchers...)
		return option
	})
}

// WithExecutableReporter registers a reporter for newly seen executables. It
// is driven by reporter.ExecutableReporterWatcher, which provides the same
// reporting behavior the process manager owned before.
func WithExecutableReporter(executableReporter reporter.ExecutableReporter) Option {
	return WithProcessWatcher(reporter.NewExecutableReporterWatcher(executableReporter))
}

// WithOnShutdown is a function that allows to configure a function to be called when the controller is shutdown.
func WithOnShutdown(onShutdown func() error) Option {
	return optFunc(func(option *controllerOption) *controllerOption {
		option.onShutdown = onShutdown
		return option
	})
}

// WithReporterFactory is a function that allows to define a custom collector reporter factory.
// If reporterFactory is not set, the default reporter will be used (reporter.NewCollector).
func WithReporterFactory(reporterFactory func(cfg *reporter.Config, nextConsumer xconsumer.Profiles) (reporter.Reporter, error)) Option {
	return optFunc(func(option *controllerOption) *controllerOption {
		option.reporterFactory = reporterFactory
		return option
	})
}

// WithProcessMetaEnricher registers a hook that is called once per process when it
// is first observed and when its executable changes. The enricher may read from /proc or other sources and store
// arbitrary key-value pairs in process.Meta.ExtraMeta. Those values are propagated
// to TraceEventMeta.ExtraMeta, where a SampleAttrProducer can attach them as
// resource or sample attributes on outgoing profiles.
func WithProcessMetaEnricher(enrichers ...process.MetaEnricher) Option {
	return optFunc(func(option *controllerOption) *controllerOption {
		option.processMetaEnrichers = append(option.processMetaEnrichers, enrichers...)
		return option
	})
}
