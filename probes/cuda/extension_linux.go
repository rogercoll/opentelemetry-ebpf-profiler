// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package cuda // import "go.opentelemetry.io/ebpf-profiler/probes/cuda"

import (
	"context"

	"go.opentelemetry.io/collector/component"

	"go.opentelemetry.io/ebpf-profiler/tracer"
)

// cudaExtension is an OTel Collector extension that exposes a tracer.Probe
// for use by the ebpf_profiler receiver.
type cudaExtension struct {
	p tracer.Probe
}

func (e *cudaExtension) Start(_ context.Context, _ component.Host) error { return nil }
func (e *cudaExtension) Shutdown(_ context.Context) error                { return nil }

// Probe returns the tracer.Probe that this extension provides.
func (e *cudaExtension) Probe() tracer.Probe { return e.p }
