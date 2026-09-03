Process Manager Simplification
==============================

# Meta

- **Author(s)**: Roger Coll
- **Start Date**: 2026-09-01
- **Goal End Date**: TBD
- **Primary Reviewers**: TBD

# Abstract

`ProcessManager` does too many things. Besides its core job (tracking process
mappings, loading stack deltas into eBPF, and symbolizing traces) it also owns
executable reporting, probe attachment, process metadata collection, trace
annotation and trace reporting. Every new feature that needs to react to process events ends up
adding more fields and more logic inside it.

This document proposes turning `ProcessManager` into a plain dispatcher of
process lifecycle events. Consumers register as a `ProcessWatcher` and
implement single-method listener interfaces for the events they care about,
owning their state and logic themselves. Trace annotation moves to the tracer
behind a `TraceDecorator` interface, and trace reporting moves with it.

Related: [#1676](https://github.com/open-telemetry/opentelemetry-ebpf-profiler/issues/1676)
(plugin/extension-point architecture),
[#186](https://github.com/open-telemetry/opentelemetry-ebpf-profiler/issues/186)
(lock contention / parallelism), and
[#1768](https://github.com/open-telemetry/opentelemetry-ebpf-profiler/pull/1768)
(late-binding resource attributes), which this proposal would address without
adding new machinery to `ProcessManager`.

# Introduction

## Context

Today, when `SynchronizeProcess` finds a new executable mapping,
`ProcessManager` itself:

- calls `exeReporter.ReportExecutable` on the (single, optional)
  `ExecutableReporter`,
- iterates the registered `ProbeAttacher`s calling `Match`/`Attach`, and
  tracks which ones attached to which PID so it can `Detach` them on exit,
- runs the `MetaEnricher` chain and stores the resulting `process.Meta`
  in its own per-PID map.

On the trace path, `HandleTrace` reads that stored metadata directly and
hardcodes which fields end up annotating each trace event.

None of these concerns belong to `ProcessManager`. They just need to know
"a process appeared", "a mapping appeared", "a process exited": signals that
`ProcessManager` is uniquely positioned to emit, but whose handling it should
not own.

## Problem Statement

The coupling causes real problems:

**Every extension grows ProcessManager.** There is no stable plugin point, so
each new consumer of process events means new fields, new config plumbing, and
new logic inside PM. PR #1768 is the latest example: to support attributes that
resolve late (OTel process context, interpreter runtime), it adds per-process
contribution slots, mapping filters, and a merge pass inside the PM. The
change is well-motivated, but it grows exactly the code we should be shrinking.

**Testing is painful.** Unit-testing any single PM behavior requires wiring up
all the others. A symbolization test still needs a stub executable reporter and
an empty attacher list. (e.g https://github.com/open-telemetry/opentelemetry-ebpf-profiler/issues/1810)

**Lock contention.** Probe attachment and executable reporting run while
`pm.mu` is write-locked, blocking concurrent trace handling. This is the
problem tracked in #186, and it can't be fixed cleanly while these callbacks
are entangled with PM's internal state.

**Trace annotation is rigid.** `HandleTrace` decides what annotates a trace by
reading `processInfo` fields directly. Adding an attribute means touching PM,
even when the attribute can be gather asynchronously.

## Success Criteria

- `ProcessManager` holds per-event lists of watchers and dispatches events to them.
  It no longer references `ExecutableReporter`, `ProbeAttacher`,
  `MetaEnricher`, or the proposed `ResourceEnricher` directly.
- Each extracted concern is testable without constructing a `ProcessManager`.
- `HandleTrace` no longer takes `pm.mu` for metadata; trace annotation goes
  through decorators that read their own state.
- Late-binding attributes (the #1768 use case) are expressible as a plain
  watcher, with no PM changes.
- No behavior change for existing users; call sites are migrated in the same
  PR that removes each old interface (breaking changes are fine, no
  deprecation cycles needed).

## Scope

In scope: the watcher and decorator interfaces, migrating the four concerns
listed above, and releasing `pm.mu` before dispatching.

Out of scope: the interpreter instance lifecycle (tracked separately in #1676),
the frame symbolization pipeline itself, and async event delivery (a natural
follow-up once dispatch is out from under the lock; see #186). The watcher
interface is a likely foundation for the interpreter refactor in #1676, but
interpreters need frame-level symbolization hooks and write eBPF state that
this document doesn't define.

# Proposed Solution

## ProcessWatcher

Anything that wants to react to process changes is provided as a
`ProcessWatcher` in the `ProcessManager` config and implements only the
listener interfaces for the events it cares about:

```go
// ProcessWatcher is the registration type. Implementations must also
// implement at least one of the listener interfaces below.
type ProcessWatcher any

type ProcessNewListener interface  { OnProcessNew(pr process.Process) }
type ProcessExecListener interface { OnProcessExec(pr process.Process) }
type MappingsListener interface    { OnMappingsSync(pr process.Process, mappings []process.RawMapping) }
type ProcessExitListener interface { OnProcessExit(pid libpf.PID) }
```

The interfaces live in the leaf package `processmanager/processwatcher`, which
only imports `libpf` and `process`. This lets any package (including
`reporter`, which `processmanager` itself imports) implement the interfaces
and assert conformance at compile time without import cycles.

Watchers are passed via `Config.ProcessWatchers` and the list is immutable
after construction. Dispatch type-asserts each watcher per event through a
small generic helper; a watcher that only listens for exits never runs on the
mapping path, and there are no no-op stubs to write. This is the same
optional-interface pattern the OTel Collector uses for extension capabilities
(`PipelineWatcher`, `ConfigWatcher`) and the standard library uses for
`io.WriterTo`/`http.Pusher`.

Considered alternatives: a funcs-struct with optional nil function fields (k8s's
`ResourceEventHandlerFuncs`) is equivalent but registers anonymous functions
instead of coherent named types; a single `Handle(event)` method with a kind tag
is the closest Go gets to a Rust enum, but forces every watcher to receive and
type-switch on every event, exactly the overhead being avoided. Per-mapping
`OnMappingAdded`/`OnMappingRemoved` events with a PM-computed `MappingInfo`
(FileID, build IDs) were prototyped and dropped: PM's sync pass is a full
re-scan rather than a diff, so a bulk `OnMappingsSync` matches what PM actually
knows, and watchers that need FileIDs compute and cache them on their own
terms.

Two event semantics worth calling out:

- `OnMappingsSync` delivers all file-backed mappings observed in the pass, not
  just executable ones, so e.g. non-executable `.dll` mappings or an
  `OTEL_CTX` memfd mapping can be observed. Watchers filter and deduplicate
  themselves: every pass delivers the full list, so a watcher that acts once
  per mapping keeps its own seen-set (the uprobe probe keeps one per PID, the
  executable reporter an LRU keyed by device/inode).
- `OnProcessExec` fires when a tracked PID replaces its image (PM already
  detects this via the executable path change). Watchers drop anything
  derived from the old image; the mapping events that follow describe the new
  one.

All events are dispatched
*without* `pm.mu` held: PM updates its internal state under the lock, then
drops it and notifies watchers. This is the same restructuring #186 needs
anyway, and it removes today's fragile rule that attachers must never call back
into PM.

## Parameter and concurrency contract

- `process.Process` is the live handle PM is using for the pass. It is not
  safe for concurrent use and is closed when the pass ends, so listeners must
  not retain it. Exception: the reader from `GetRemoteMemory()` is safe to
  keep and use concurrently.
- The `RawMapping` slice passed to `OnMappingsSync` is a fresh copy with
  `Path` interned by PM before dispatch. It is self-contained and safe to
  store.
- Data a decorator places into `TraceEventMeta` flows to the reporter and is
  read from other goroutines later. Decorators must never mutate it after
  publishing: build a fresh value and replace, don't edit in place.

Dispatch guarantees: events for the same PID are delivered in order and never
concurrently; events for different PIDs may be concurrent (not today, but
after #186, so watchers should assume it now); `DecorateTrace` may run
concurrently with any event. A watcher whose state is written by events and
read by `DecorateTrace` must synchronize it, e.g. with its own `RWMutex` or an
atomic snapshot swap.

The same-PID ordering is a hard guarantee, not an implementation detail:
`MetadataStore` relies on `OnProcessNew` having populated env vars before
`OnMappingsSync` resolves the OTel process context from them. Any future
parallelization of the sync path (#186) must preserve per-PID ordering.

Two contracts that the PoC surfaced:

- Dispatch is synchronous. A slow listener stalls the synchronization pass for
  that PID, so listener methods must be fast; heavy work (uploads, hashing
  large files) should be offloaded or cached, as the executable reporter
  watcher does with its LRU.
- `ProcessWatcher` is `any`, so a watcher implementing none of the listener
  interfaces (e.g. from a typo'd method signature) registers silently and
  never fires. In-tree implementations guard against this with compile-time
  `var _` assertions against the `processwatcher` interfaces; external
  implementations should do the same.

Watcher registration order is the dispatch order per event. If one watcher
depends on another's state in a callback, the dependency must be registered
first.

## Locking

`pm.mu` is not eliminated. It still protects PM's core maps (mappings,
interpreter instances, caches, exit events). What changes is its scope:

- Watcher dispatch is always outside it.
- `HandleTrace` currently takes a read lock for `metaForPID` and interpreter
  instance lookup. With `MetadataStore`, the metadata read goes away; trace
  annotation reads the store's own lock instead. The interpreter read lock
  remains for symbolization on frame cache misses and per-trace resource
  release.

The write lock in `SynchronizeProcess` is held only while mutating PM's own
maps, not while calling watchers. This is what makes #186's per-PID goroutine
pool viable. Full lock elimination would require moving interpreter state out
of PM, which is the #1676 work.

The existing consumers become small, self-contained watchers:

- **ExecutableReporter** → `reporter.ExecutableReporterWatcher`, a
  `MappingsListener` that drives any `reporter.ExecutableReporter` with the
  behavior PM owned: LRU dedup with the old `elfInfoCache` size and TTL,
  FileID computation with an unprivileged fallback, GNU/Go build IDs and
  debuglink extraction. It also covers the dotnet interpreter's separate
  reporting path by matching `.dll` mappings even when mapped non-executable,
  which let the `exeReporter` parameter be removed from every interpreter's
  `SynchronizeMappings`. The collector's `WithExecutableReporter` option keeps
  its signature as a thin wrapper, so existing users migrate with no code
  change. As a bonus, multiple reporters can now be registered (today only
  one fits).
- **ProbeAttacher** → deleted; probes implement `MappingsListener` and
  `ProcessExitListener` directly. PM's `attachedProbes` bookkeeping moves into
  each probe, where it belongs. One wrinkle: probes are registered as watchers
  at configuration time but their eBPF program only loads when the probe is
  enabled, so a probe ignores `OnMappingsSync` (without marking mappings as
  seen) until loaded, and drops late-arriving attachments after unload.
- **Process metadata** → a single `MetadataStore` watcher that runs the
  enricher chain on `OnProcessNew`/`OnProcessExec`, resolves the OTel process
  context on `OnMappingsSync`, drops entries on `OnProcessExit`, and owns its
  maps behind its own lock; taking metadata reads off `pm.mu` entirely.
  Metadata and process context started as two watchers but merged: the
  context resolution reads env vars the enrichers gathered, and one store
  under one lock removes the cross-store read.

## TraceDecorator

Trace annotation and reporting leave `ProcessManager` entirely. PM's
`HandleTrace` symbolizes the raw frames and returns the trace with its
eBPF-sourced base metadata; the tracer runs the decorators and reports:

```go
// tracer package
type TraceDecorator interface {
    DecorateTrace(trace *libpf.Trace, meta *samples.TraceEventMeta)
}
```

The interface lives in the tracer because that is where the trace event is
assembled and handed to the reporter; PM neither holds a reporter reference
nor knows what annotates a trace. Each decorator does a read of its own
per-PID state, no I/O, no `pm.mu`.

This is what makes the #1768 use case fall out naturally. That PR needs
attributes which resolve *after* first observation (a process context region
published later, a runtime known only once an interpreter attaches). Its answer
is a new enricher pipeline inside PM, because PM is currently the only place
with access to both the mapping pass and the trace path. With watchers, the
same enricher is just a component that updates its per-PID state on
`OnMappingsSync` and emits it in `DecorateTrace`. Different enrichers update on
different triggers (some on process new/exit, others on every mapping pass)
and PM doesn't need to know or care which.

`MetadataStore` uses the same mechanism for today's annotations (executable
path, container ID, env vars), so `HandleTrace` stops reading `processInfo`
fields directly.

**Worked example: the OTel process context.** Today it has five touch points
inside `SynchronizeProcess`: spotting the `OTEL_CTX` mapping during the maps
pass, carrying its address to the end of the pass, resolving it from remote
memory, invalidating it on exec, and serving the result to `HandleTrace`. As
part of `MetadataStore` it becomes self-contained: match the context mapping
and resolve it in `OnMappingsSync`, reset on `OnProcessExec`, drop on
`OnProcessExit`, and set the resource attributes in `DecorateTrace`.

## What ProcessManager keeps

Mapping state, the eBPF maps, the ELF/frame caches, stack delta loading,
interpreter instances, and symbolization. That's its actual job. Everything
else becomes a watcher.

## Rollout

1. **Lock release before dispatch.** Restructure `newFrameMapping` and
   `processPIDExit` to drop `pm.mu` before invoking the current callbacks.
2. **Watcher + decorator interfaces, MetadataStore.** Move metadata
   collection and trace annotation out of PM. Internal refactor only.
3. **Executable reporter and probe attacher migration.** Remove
   `Config.ExecutableReporter`, the `ProbeAttacher` interface, and the
   `exeReporter` parameter from `interpreter.Instance.SynchronizeMappings`;
   provide `reporter.ExecutableReporterWatcher`; update all call sites in the
   same PR. `WithExecutableReporter` keeps its signature.
4. **Resource enrichment.** Implement the #1768 use case as a watcher
   (rebasing its enrichers from #1770/#1771), removing the need for the
   `procmeta` pipeline inside PM.

# Testing Strategy

Each watcher is a plain struct: tests call its `On*` and `DecorateTrace`
methods directly with synthetic inputs, no PM fixture needed. The PoC bears
this out: `ExecutableReporterWatcher` is tested in the `reporter` package with
a mock `process.Process` and a capturing reporter, covering the ELF path
(FileID, Go build ID, dedup across passes) and the dotnet `.dll` path — tests
that previously required constructing a full `ProcessManager`. `MetadataStore`
is exercised through `SynchronizeProcess` with the store registered as a
watcher, asserting enricher call counts on new/exec and metadata via
`MetaForPID`.

The `MetaEnricher` interface doesn't change, only how it's wired in.
`ProbeAttacher` is removed, so probe tests target the listener methods
directly.

# Decision

_To be filled in after review._ A PoC implementing the full proposal exists
and informed the interface shapes above. Findings from it:

- The bulk `OnMappingsSync` event replaced the per-mapping add/remove events:
  PM re-scans mappings rather than diffing them, so a per-pass event with
  watcher-side dedup is the honest contract.
- Config-time registration replaced `pm.Subscribe`: the watcher list is fixed
  at construction, removing registration-order races and a mutation API.
- `TraceDecorator` moved to the tracer along with trace reporting; PM's
  `HandleTrace` became a pure transformation from eBPF trace to symbolized
  trace plus metadata.
- The listener interfaces landed in the leaf package
  `processmanager/processwatcher` so that `reporter` and the probes can
  assert conformance at compile time despite `processmanager` importing
  `reporter`.
- Feature parity of the extracted executable reporting (including the dotnet
  assembly path) is demonstrated by `reporter.ExecutableReporterWatcher` and
  its tests, with no PM involvement.
