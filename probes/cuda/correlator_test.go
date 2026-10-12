// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package cuda

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

// launchTrace builds a launch trace as the tracer delivers it.
func launchTrace(pid libpf.PID, correlationID int64) *libpf.EbpfTrace {
	trace := &libpf.EbpfTrace{PID: pid, Value: correlationID, KTime: 1}
	trace.FrameDataBuf[0] = 0xabc
	trace.FrameData = trace.FrameDataBuf[:1]
	return trace
}

func kernel(pid uint32, correlationID, start, end uint64) kernelEvent {
	return kernelEvent{PID: pid, CorrelationID: correlationID, Start: start, End: end}
}

func TestKernelBeforeLaunch(t *testing.T) {
	c := newCorrelator(func(*libpf.EbpfTrace) { t.Fatal("unexpected report") })

	c.onKernel(kernel(10, 5, 1000, 1500))
	trace := launchTrace(10, 5)
	require.True(t, c.onLaunch(trace))
	assert.Equal(t, int64(500), trace.Value)
	assert.Equal(t, int64(1000), trace.KTime)
	assert.Empty(t, c.kernels)
}

func TestLaunchBeforeKernel(t *testing.T) {
	var reported []*libpf.EbpfTrace
	c := newCorrelator(func(trace *libpf.EbpfTrace) { reported = append(reported, trace) })

	trace := launchTrace(10, 5)
	require.False(t, c.onLaunch(trace))
	assert.Empty(t, reported)

	c.onKernel(kernel(10, 5, 1000, 1500))
	require.Len(t, reported, 1)
	assert.Equal(t, int64(500), reported[0].Value)
	assert.Equal(t, int64(1000), reported[0].KTime)
	assert.Empty(t, c.launches)
}

func TestCopyTraceOwnsFrameData(t *testing.T) {
	trace := launchTrace(10, 5)
	held := copyTrace(trace)

	trace.FrameDataBuf[0] = 0 // the pool reuses the original
	assert.Equal(t, []uint64{0xabc}, held.FrameData)
	assert.Same(t, &held.FrameDataBuf[0], &held.FrameData[0])
}

func TestForget(t *testing.T) {
	c := newCorrelator(func(*libpf.EbpfTrace) {})

	c.onLaunch(launchTrace(10, 5))
	c.onKernel(kernel(20, 7, 0, 1))
	c.forget(10)
	assert.Empty(t, c.launches)
	assert.Len(t, c.kernels, 1)
}
