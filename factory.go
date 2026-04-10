// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:generate sh -c "go tool -modfile=tools.mod mdatagen metadata.yaml 2>/dev/null; sed -i 's/^package opentelemetry-ebpf-profiler$/package collector/' generated_*test.go 2>/dev/null; go tool -modfile=tools.mod mdatagen metadata.yaml 2>/dev/null; sed -i 's/^package opentelemetry-ebpf-profiler$/package collector/' generated_*test.go 2>/dev/null; gofmt -w generated_*test.go 2>/dev/null; exit 0"

package collector // import "go.opentelemetry.io/ebpf-profiler"

import (
	"errors"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/xreceiver"

	"go.opentelemetry.io/ebpf-profiler/config"
	"go.opentelemetry.io/ebpf-profiler/internal/metadata"
)

var errInvalidConfig = errors.New("invalid config")

// NewFactory creates a factory for the receiver.
func NewFactory() receiver.Factory {
	return xreceiver.NewFactory(
		metadata.Type,
		defaultConfig,
		xreceiver.WithProfiles(BuildProfilesReceiver(), metadata.ProfilesStability))
}

func defaultConfig() component.Config {
	return &config.Config{
		ReporterInterval:       5 * time.Second,
		ReporterJitter:         0.2,
		MonitorInterval:        5 * time.Second,
		SamplesPerSecond:       20,
		ProbabilisticInterval:  1 * time.Minute,
		ProbabilisticThreshold: 100,
		Tracers:                "all",
		ClockSyncInterval:      3 * time.Minute,
		MaxGRPCRetries:         5,
		MaxRPCMsgSize:          32 << 20, // 32 MiB,
		BPFFSRoot:              "/sys/fs/bpf/",
		ErrorMode:              config.PropagateError,
	}
}
