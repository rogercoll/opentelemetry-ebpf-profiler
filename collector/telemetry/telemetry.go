// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package telemetry re-exports the auto-generated TelemetryBuilder so that
// packages outside the collector tree (tracer, processmanager, interpreter, …)
// can reference it without importing collector/internal/metadata directly.
package telemetry // import "go.opentelemetry.io/ebpf-profiler/collector/telemetry"

import (
	"go.opentelemetry.io/ebpf-profiler/collector/internal/metadata"
)

type TelemetryBuilder = metadata.TelemetryBuilder

type TelemetryBuilderOption = metadata.TelemetryBuilderOption

var NewTelemetryBuilder = metadata.NewTelemetryBuilder
