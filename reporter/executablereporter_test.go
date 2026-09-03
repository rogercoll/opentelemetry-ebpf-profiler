// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter_test

import (
	"bytes"
	"debug/elf"
	"errors"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/reporter"
)

// capturingReporter collects the reported executables like an out-of-tree
// symbol uploader would.
type capturingReporter struct {
	mu       sync.Mutex
	reported []*reporter.ExecutableMetadata
}

func (c *capturingReporter) ReportExecutable(args *reporter.ExecutableMetadata) {
	c.mu.Lock()
	c.reported = append(c.reported, args)
	c.mu.Unlock()
}

func (c *capturingReporter) byFileName(name string) *reporter.ExecutableMetadata {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, re := range c.reported {
		if re.MappingFile.Value().FileName.String() == name {
			return re
		}
	}
	return nil
}

// mockProcess implements process.Process for the methods OnMappingsSync uses.
// CalculateMappingFileID always returns an error to exercise the fallback path
// (os.Open + FileIDFromExecutableReader), which does not require elevated
// privileges.
type mockProcess struct {
	pid libpf.PID
}

func (p *mockProcess) PID() libpf.PID                                            { return p.pid }
func (p *mockProcess) GetMachineData() process.MachineData                       { return process.MachineData{} }
func (p *mockProcess) GetProcessMeta([]process.MetaEnricher) process.Meta        { return process.Meta{} }
func (p *mockProcess) GetExe() (libpf.String, error)                             { return libpf.Intern(""), nil }
func (p *mockProcess) IterateMappings(func(process.RawMapping) bool) (uint32, error) {
	return 0, nil
}
func (p *mockProcess) GetThreads() ([]process.ThreadInfo, error)      { return nil, nil }
func (p *mockProcess) GetRemoteMemory() remotememory.RemoteMemory     { return remotememory.RemoteMemory{} }
func (p *mockProcess) OpenMappingFile(*process.RawMapping) (process.ReadAtCloser, error) {
	return nil, errors.New("not implemented")
}
func (p *mockProcess) GetMappingFileLastModified(*process.RawMapping) int64 { return 0 }
func (p *mockProcess) CalculateMappingFileID(*process.RawMapping) (libpf.FileID, error) {
	return libpf.FileID{}, errors.New("no map_files access in tests")
}
func (p *mockProcess) Close() error { return nil }
func (p *mockProcess) OpenELF(filePath string) (*pfelf.File, error) {
	return pfelf.Open(filePath)
}

// TestExecutableReporterWatcher verifies the watcher reports the test binary
// once (with FileID and Go build ID) and deduplicates on a second call.
func TestExecutableReporterWatcher(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux /proc ELF")
	}

	exe, err := os.Executable()
	require.NoError(t, err)
	info, err := os.Stat(exe)
	require.NoError(t, err)

	mappings := []process.RawMapping{{
		Vaddr:  0x400000,
		Length: uint64(info.Size()),
		Flags:  elf.PF_R | elf.PF_X,
		Device: 1,
		Inode:  2,
		Path:   exe,
	}}

	capture := &capturingReporter{}
	w := reporter.NewExecutableReporterWatcher(capture)
	pr := &mockProcess{pid: 42}

	w.OnMappingsSync(pr, mappings)

	reported := capture.byFileName(path.Base(exe))
	require.NotNil(t, reported, "test executable not reported")
	mf := reported.MappingFile.Value()
	require.NotEqual(t, libpf.FileID{}, mf.FileID)
	require.NotEmpty(t, mf.GoBuildID)

	// Second call must not report the already-seen executable.
	before := len(capture.reported)
	w.OnMappingsSync(pr, mappings)
	require.Len(t, capture.reported, before)
}

// TestExecutableReporterWatcherReportsDotnetAssemblies verifies that .NET
// assemblies are reported even when mapped without the executable flag.
func TestExecutableReporterWatcherReportsDotnetAssemblies(t *testing.T) {
	content := []byte("MZ fake PE assembly")
	dll := filepath.Join(t.TempDir(), "ProfileDemo.dll")
	require.NoError(t, os.WriteFile(dll, content, 0o600))

	mappings := []process.RawMapping{{
		Vaddr:  0x1000,
		Length: uint64(len(content)),
		Flags:  elf.PF_R,
		Device: 1,
		Inode:  2,
		Path:   dll,
	}}

	capture := &capturingReporter{}
	w := reporter.NewExecutableReporterWatcher(capture)
	w.OnMappingsSync(&mockProcess{pid: 42}, mappings)

	re := capture.byFileName("ProfileDemo.dll")
	require.NotNil(t, re, ".NET assembly not reported")
	wantFileID, err := libpf.FileIDFromExecutableReader(bytes.NewReader(content))
	require.NoError(t, err)
	require.Equal(t, wantFileID, re.MappingFile.Value().FileID)
}
