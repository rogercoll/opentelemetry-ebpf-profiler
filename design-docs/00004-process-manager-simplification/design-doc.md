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
implement single-method listener interfaces for the events they care about
(and optionally a `TraceDecorator` for annotating traces), owning their state
and logic themselves.

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
- `HandleTrace` no longer takes `pm.mu`; trace annotation goes through
  decorators that read their own state.
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

Anything that wants to react to process changes registers as a `ProcessWatcher`
and implements only the listener interfaces for the events it cares about:

```go
// ProcessWatcher is the registration type. Implementations must also
// implement at least one of the listener interfaces below.
type ProcessWatcher interface{}

type ProcessNewListener interface    { OnProcessNew(pr process.Process) }
type ProcessExecListener interface   { OnProcessExec(pr process.Process) }
type MappingAddedListener interface  { OnMappingAdded(pr process.Process, mapping *process.RawMapping, info MappingInfo) }
type MappingRemovedListener interface{ OnMappingRemoved(pid libpf.PID, fileID libpf.FileID, vaddr uint64) }
type ProcessExitListener interface   { OnProcessExit(pid libpf.PID) }
```

`pm.Subscribe(w ProcessWatcher)` type-asserts once at registration and sorts
the watcher into per-event dispatch lists. Dispatch is then a plain slice
iteration: a watcher that only listens for exits never appears on the mapping
path, and there are no no-op stubs to write. This is the same optional-interface
pattern the OTel Collector uses for extension capabilities (`PipelineWatcher`,
`ConfigWatcher`) and the standard library uses for `io.WriterTo`/`http.Pusher`.

Considered alternatives: a funcs-struct with optional nil function fields (k8s's
`ResourceEventHandlerFuncs`) is equivalent but registers anonymous functions
instead of coherent named types; a single `Handle(event)` method with a kind tag
is the closest Go gets to a Rust enum, but forces every watcher to receive and
type-switch on every event, exactly the overhead being avoided.

`MappingInfo` carries what PM has already computed for the mapping (FileID,
build IDs), so watchers don't re-open ELFs.

Two event semantics worth calling out:

- `OnMappingAdded` is not limited to executable file-backed mappings. PM's
  mapping pass already iterates every entry in `/proc/PID/maps`; watchers
  declare which mappings interest them with a cheap predicate (the same shape
  as today's `ProbeAttacher.Match`), so e.g. a non-executable `OTEL_CTX`
  memfd mapping can be observed without every watcher seeing every mapping.
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
- `RawMapping` is passed by value, with `Path` interned by PM before dispatch.
  It is a self-contained snapshot, safe to store.
- `MappingInfo`, `libpf.PID`, and `libpf.FileID` are immutable values.
- Data a decorator places into `TraceEventMeta` flows to the reporter and is
  read from other goroutines later. Decorators must never mutate it after
  publishing: build a fresh value and replace, don't edit in place.

Dispatch guarantees: events for the same PID are delivered in order and never
concurrently; events for different PIDs may be concurrent (not today, but
after #186, so watchers should assume it now); `DecorateTrace` may run
concurrently with any event. A watcher whose state is written by events and
read by `DecorateTrace` must synchronize it, e.g. with its own `RWMutex` or an
atomic snapshot swap.

Watcher registration order is the dispatch order per event. If one watcher
depends on another's state in a callback, the dependency must be registered
first.

## Locking

`pm.mu` is not eliminated. It still protects PM's core maps (mappings,
interpreter instances, caches, exit events). What changes is its scope:

- Watcher dispatch is always outside it.
- `HandleTrace` currently takes a read lock for `metaForPID` and interpreter
  instance lookup. With `MetadataStore`, the metadata read goes away. The
  interpreter lookup stays but only fires on a frame cache miss, making the
  common path lock-free.

The write lock in `SynchronizeProcess` is held only while mutating PM's own
maps, not while calling watchers. This is what makes #186's per-PID goroutine
pool viable. Full lock elimination would require moving interpreter state out
of PM, which is the #1676 work.

The existing consumers become small, self-contained watchers:

- **ExecutableReporter** → a watcher that forwards `OnMappingAdded` to
  `ReportExecutable`. As a bonus, multiple reporters can now be registered
  (today only one fits).
- **ProbeAttacher** → a watcher that runs `Match`/`Attach` on
  `OnMappingAdded` and `Detach` on `OnProcessExit`. PM's `attachedProbes`
  bookkeeping moves into the watcher, where it belongs.
- **Process metadata** → a `MetadataStore` watcher that runs the enricher
  chain on `OnProcessNew`, drops entries on `OnProcessExit`, and owns its map
  behind its own lock; taking metadata reads off `pm.mu` entirely.

## TraceDecorator

Watchers that annotate traces additionally implement:

```go
type TraceDecorator interface {
    DecorateTrace(pid libpf.PID, meta *samples.TraceEventMeta)
}
```

`HandleTrace` builds the base event, then calls `DecorateTrace` on each
registered decorator (sorted into its own list at `Subscribe` time, like the
other listeners). Each decorator does a read of its own per-PID
state, no I/O, no `pm.mu`.

This is what makes the #1768 use case fall out naturally. That PR needs
attributes which resolve *after* first observation (a process context region
published later, a runtime known only once an interpreter attaches). Its answer
is a new enricher pipeline inside PM, because PM is currently the only place
with access to both the mapping pass and the trace path. With watchers, the
same enricher is just a component that updates its per-PID state on
`OnMappingAdded` and emits it in `DecorateTrace`. Different enrichers update on
different triggers (some on process new/exit, others on every new mapping)
and PM doesn't need to know or care which.

`MetadataStore` uses the same mechanism for today's annotations (executable
path, container ID, env vars), so `HandleTrace` stops reading `processInfo`
fields directly.

**Worked example: the OTel process context.** Today it has five touch points
inside `SynchronizeProcess`: spotting the `OTEL_CTX` mapping during the maps
pass, carrying its address to the end of the pass, resolving it from remote
memory, invalidating it on exec, and serving the result to `HandleTrace`. As a
watcher it becomes one self-contained component: match the context mapping
in `OnMappingAdded` and resolve it, reset on `OnProcessExec`, drop on
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
3. **Executable reporter and probe attacher migration.** Add `pm.Subscribe`,
   remove `Config.ExecutableReporter` and `RegisterProbeAttacher`, update all
   call sites in the same PR.
4. **Resource enrichment.** Implement the #1768 use case as a watcher
   (rebasing its enrichers from #1770/#1771), removing the need for the
   `procmeta` pipeline inside PM.

# Testing Strategy

Each watcher is a plain struct: tests call its `On*` and `DecorateTrace`
methods directly with synthetic inputs, no PM fixture needed. PM tests replace
the watcher lists with a recording stub and assert the event sequence for a
given `/proc/PID/maps` diff. A dedicated test verifies a watcher can safely
call PM read methods from its callbacks (possible once dispatch is outside the
lock).

Existing probe and collector tests keep working: the `ProbeAttacher` and
`MetaEnricher` interfaces themselves don't change, only how they're wired in.

# Decision

_To be filled in after review._
