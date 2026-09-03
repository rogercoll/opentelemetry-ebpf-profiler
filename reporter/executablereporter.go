// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	"os"
	"path"
	"strings"
	"time"

	lru "github.com/elastic/go-freelru"

	"go.opentelemetry.io/ebpf-profiler/internal/log"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/processmanager/processwatcher"
	"go.opentelemetry.io/ebpf-profiler/util"
)

var _ processwatcher.MappingsListener = (*ExecutableReporterWatcher)(nil)

const (
	// The reported executables cache mirrors the process manager's
	// elfInfoCache, which gated the reporting when the process manager owned
	// it.
	executablesCacheSize = 16384
	executablesCacheTTL  = 6 * time.Hour
)

// ExecutableReporterWatcher drives an ExecutableReporter from the process
// manager's mapping synchronization events, with the behavior the process
// manager provided when it owned the reporting: each executable file is
// reported once per cache lifetime, with its file ID, build IDs and debug
// link. .NET assemblies (.dll) are included even when mapped non-executable;
// their PE debug directory GUID is not extracted, a .NET aware reporter can
// read it with the standard library debug/pe package.
type ExecutableReporterWatcher struct {
	reporter ExecutableReporter

	// seen gates reporting to once per executable file.
	seen *lru.SyncedLRU[util.OnDiskFileIdentifier, libpf.Void]
}

// NewExecutableReporterWatcher returns a process watcher reporting newly seen
// executables to r.
func NewExecutableReporterWatcher(r ExecutableReporter) *ExecutableReporterWatcher {
	seen, err := lru.NewSynced[util.OnDiskFileIdentifier, libpf.Void](
		executablesCacheSize, util.OnDiskFileIdentifier.Hash32)
	if err != nil {
		// Unreachable: NewSynced only fails on invalid size or hasher.
		panic(err)
	}
	seen.SetLifetime(executablesCacheTTL)
	return &ExecutableReporterWatcher{reporter: r, seen: seen}
}

// OnMappingsSync implements processmanager.MappingsListener.
func (w *ExecutableReporterWatcher) OnMappingsSync(pr process.Process,
	mappings []process.RawMapping) {
	for i := range mappings {
		m := &mappings[i]
		// Executable mappings plus .NET assemblies: PE files are often mapped
		// without the executable flag and run through the JIT, so they are
		// matched by suffix, like the dotnet interpreter does.
		if m.IsAnonymous() ||
			(!m.IsExecutable() && !strings.HasSuffix(m.Path, ".dll")) {
			continue
		}
		key := m.GetOnDiskFileIdentifier()
		if _, ok := w.seen.Get(key); ok {
			continue
		}

		// The file ID is the generic file hash: it matches the file ID that
		// symbolized frames of this executable carry. The path-based hash is
		// the fallback for environments where /proc/PID/map_files needs more
		// privileges than available.
		fileID, err := pr.CalculateMappingFileID(m)
		if err != nil {
			var f *os.File
			if f, err = os.Open(m.Path); err == nil {
				fileID, err = libpf.FileIDFromExecutableReader(f)
				f.Close()
			}
			if err != nil {
				log.Debugf("Failed to compute file ID of %s: %v", m.Path, err)
				continue
			}
		}

		var gnuBuildID, goBuildID, debuglinkFileName string
		if ef, err := pr.OpenELF(m.Path); err == nil {
			gnuBuildID, _ = ef.GetBuildID()
			if ef.IsGolang() {
				goBuildID, _ = ef.GetGoBuildID()
			}
			debuglinkFileName = ef.DebuglinkFileName(m.Path, pr)
			ef.Close()
		}

		w.seen.Add(key, libpf.Void{})
		w.reporter.ReportExecutable(&ExecutableMetadata{
			MappingFile: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
				FileID:     fileID,
				FileName:   libpf.Intern(path.Base(m.Path)),
				GnuBuildID: gnuBuildID,
				GoBuildID:  goBuildID,
			}),
			Process:           pr,
			Mapping:           m,
			DebuglinkFileName: debuglinkFileName,
		})
	}
}
