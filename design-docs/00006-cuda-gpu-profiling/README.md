CUDA GPU Profiling (work in progress)
====================================

# Meta

- **Author(s)**: Roger Coll
- **Start Date**: 2026-10-10
- **Status**: Prototype on branch `cuda_gpu_profiling`, paused
- **Agent**: [rogercoll/cuda-gpu-profiling](https://github.com/rogercoll/cuda-gpu-profiling)

# Abstract

This branch adds a `cuda` probe extension that turns GPU kernel executions
into a `gpu_time` profile. Each sample is the CPU stack that launched a
kernel, weighted by the nanoseconds the kernel ran on the GPU, with the
kernel itself as the leaf frame. The GPU data comes from a small CUPTI agent
injected into CUDA processes (`CUDA_INJECTION64_PATH`), which exposes kernel
launches and completions as USDT probes. This document explains what the
branch changes, why, and what is left before it could be proposed upstream.

# Motivation

CPU profiles cannot answer "which code is responsible for GPU time":

- Kernel launches are asynchronous. Launching a 50 µs kernel and a 50 ms
  kernel costs the CPU the same few microseconds, so launch sites are nearly
  invisible in CPU samples.
- The cost shows up elsewhere: the CPU blocks in `cudaDeviceSynchronize` (or a
  blocking copy), so CPU profiles blame the wait, not the code that queued the
  work.

The GPU and its driver are invisible to the kernel, so eBPF alone cannot see
kernel durations. NVIDIA's CUPTI can, but only from inside the process. The
design splits the work accordingly:

- An **in-process agent** uses CUPTI to observe launches (callback API) and
  kernel executions (activity API).
- The **profiler** captures the CPU stack at launch with its existing
  unwinders (all interpreters for free), joins it with the kernel record by
  CUPTI's correlation ID, and reports GPU time.

The same split is used by Parca (`parcagpu`, USDT based) and zymtrace
(uprobe on an exported marker function plus a local socket).

# Architecture

```
CUDA process                                     ebpf-profiler
────────────                                     ─────────────
app ─ cuLaunchKernel ─► CUPTI callback
                         └─ USDT gpuprofiling:launch(corr) ─► kprobe__usdt_arg0
                                                              collect_trace(value = corr)
                                                              └─ PreHandleTrace ─┐
GPU runs kernel                                                                  │
app ─ cudaDeviceSynchronize ─► agent flushes CUPTI activity                      ├─ correlator
                         └─ USDT gpuprofiling:kernel(corr, start, end, ...) ─►   │  joins by
                                                              kprobe__cuda_kernel│  (pid, corr)
                                                              ring buffer ───────┘
                                                                                 │
                              gpu_time sample: launch stack + kernel leaf frame ◄┘
                              value = end - start, timestamp = start
```

## USDT contract

Provider `gpuprofiling`, kept vendor neutral so a ROCm agent could emit the
same probes:

| Probe | Arguments (register) | Fired |
|---|---|---|
| `launch` | `correlation_id` (rdi / x0) | On the app thread at each `cuLaunchKernel` |
| `kernel` | `correlation_id, start, end, device_id, stream_id, name` (rdi, rsi, rdx, rcx, r8, r9 / x0..x5) | Per kernel record CUPTI delivers |

- `start`/`end` are `CLOCK_MONOTONIC` nanoseconds: the agent registers a CUPTI
  timestamp callback, so GPU times use the same clock as `bpf_ktime_get_ns`
  and the profiler's `ktime → unix` conversion.
- `name` is a pointer to the mangled kernel name, valid while the probe fires.
- **Arguments are pinned to the calling-convention registers.** The profiler
  reads them from fixed `pt_regs` fields instead of parsing each site's SDT
  argument spec. Parsing per-site specs would need `bpf_get_attach_cookie`
  (Linux 5.15), while the profiler supports 5.10. The memory profiling work
  (PR #1746) reads its USDT arguments the same way. The agent emits its SDT
  notes with an `asm!` macro that forces the registers; the notes still
  describe them, so bpftrace and other tools work.

# Changes on this branch

## `probes/cuda` (new)

- `cuda.go`: the probe extension.
  - Registers the `gpu_time` / `nanoseconds` sample type (`ReportValues`).
  - Loads two programs and the probe-owned `cuda_kernel_events` ring buffer.
  - `Match`: mappings named `libcudaprofiling.so`.
  - `Attach`: discovers the agent's USDT notes with `usdt.Discover` through
    the mapping's `/proc/self/fd/N` and attaches `kprobe__usdt_arg0` at
    `launch` and `kprobe__cuda_kernel` at `kernel`, PID-filtered, by file
    offset (`UprobeOptions.Address`).
  - Implements `PreTraceHandler` to hand launch traces to the correlator, and
    reads kernel events from the ring buffer.
- `correlator.go`: joins launch traces and kernel records by
  `(pid, correlation_id)`. They arrive through different pipelines in either
  order (kernel records usually first: their ring buffer wakes the reader on
  every event, while traces are polled), so whichever comes first waits.
  - Launch traces are copied out of the trace pool while they wait
    (`FrameData` re-pointed at the copy's buffer) and returned `false` from
    `PreHandleTrace`; once joined they are reported through
    `ProbeContext.ReportTrace`.
  - A joined trace gets `Value = end - start`, `KTime = start` and the kernel
    as a `CUDAFrame` leaf frame, demangled without parameters
    (`_Z12softmax_rowsPfi` → `softmax_rows`, via `ianlancetaylor/demangle`).
  - `forget(pid)` drops pending entries when the process exits (`Detach`).
- `correlator_test.go`: both arrival orders, trace copy ownership, `forget`
  and demangling.
- Extension boilerplate copied from `probes/uprobe` (`factory_*`,
  `extension_linux.go`, `metadata.yaml`, `internal/metadata`).

## `support/ebpf`

- `usdt_args.h` (new): `USDT_ARG0..5(ctx)` for x86_64 and aarch64.
- `generic_probe.ebpf.c`: `kprobe__usdt_arg0`, the generic probe with the
  first USDT argument as the trace value. Not CUDA specific.
- `cuda_usdt.ebpf.c` (new): `kprobe__cuda_kernel` reads the six arguments and
  up to 128 bytes of the name (`bpf_probe_read_user_str`) into a
  `CudaKernelEvent` and sends it through `cuda_kernel_events`. No unwinding.
- `bpfdefs.h`: `bpf_probe_read_user_str` declaration.
- `frametypes.h`: `FRAME_MARKER_CUDA` (0xE), only used from Go.

## `tracer`

- `HandleTrace` is split: pre-handlers, then `reportTrace` (symbolize,
  report, post-handlers). `reportTrace` holds `reportMu`, so a probe goroutine
  reporting a held trace and the controller's trace goroutine never symbolize
  or report concurrently.
- `ProbeContext.ReportTrace`: lets a probe report a trace it held back in
  `PreHandleTrace`. This is the generic "decide when to emit" hook any
  two-phase probe needs (allocation/free pairs would fit too).
- `loadAllMaps` skips `cuda_kernel_events`, like `sched_times`: the probe
  creates and owns it.

## `libpf`, `processmanager`, `support`

- `libpf`: `CUDAFrame` frame type and `CUDA` interpreter type (exported as
  `profile.frame.type = "cuda"`); `EbpfTrace.LeafFrames`, synthetic frames a
  probe places above the unwound stack.
- `processmanager.HandleTrace`: appends `LeafFrames` first (frames are leaf
  first), outside the per-frame symbolization cache.
- `support/types_def.go`, `support/types.go`: `FrameMarkerCUDA`.

## Build

- `cmd/otelcol-ebpf-profiler/manifest.yaml`: includes `probes/cuda`.
- `go.mod`/`go.sum`: `github.com/ianlancetaylor/demangle`.

# Trying it

The agent repository has scripts to set up a GPU VM, build and run test apps
with the agent (`scripts/remote-test.sh`), and run this collector on the VM
with the OTLP port tunneled back (`scripts/remote-profiler.sh`). Its test
apps: `pipeline` (training-like loop with a naive vs tiled matmul and atomic
contention) and `inference` (the same tiny model batched and unbatched).

Collector configuration (`cmd/otelcol-ebpf-profiler/cuda.example.yaml`
locally; the `.gitignore` pattern `otelcol-ebpf-profiler` ignores it):

```yaml
receivers:
  profiling:
    probes: [cuda]
extensions:
  cuda:
exporters:
  debug:
  otlp/local:
    endpoint: "${env:OTEL_EXPORTER_OTLP_ENDPOINT:-127.0.0.1:4317}"
    tls:
      insecure: true
service:
  extensions: [cuda]
  pipelines:
    profiles:
      receivers: [profiling]
      exporters: [debug, otlp/local]
```

Run with `--feature-gates=+service.profilesSupport` as root.

Observed on a Tesla T4 with `pipeline`: `forward_naive` 44% and
`forward_tiled` 27% of GPU time for the same math, while the CPU profile of
the same run shows mostly `cudaDeviceSynchronize`.

# What is left

## Correctness

- **Unmatched entries leak until the process exits.** A kernel launched
  before the profiler attached, or a dropped launch trace, leaves an entry in
  the correlator for the process lifetime. Needs a bound (size cap or age).
- **Exit race.** `forget(pid)` on `Detach` drops kernel records whose launch
  traces are still in the trace pipeline; those launches then wait forever.
  Short-lived processes lose their last samples.
- **CUDA graphs.** One `cuGraphLaunch` correlation ID yields many kernel
  records; only the first is joined.
- **Time-sliced GPUs.** With several processes on one GPU, a kernel's
  `end - start` can include time the GPU served another context, so shares
  can be inflated under contention.
- **Kernel frames from the uprobe trap.** Launch traces may carry kernel
  frames of the int3 handling, which is noise for a uprobe (PR #1746 skips
  them).

## Coverage

- Only `cuLaunchKernel`. Missing: `cuLaunchKernelEx`, `_ptsz` variants,
  cooperative launches, `cuGraphLaunch` (agent and profiler).
- Only kernels: memcpy/memset activity is not recorded.
- Implicit syncs (blocking memcpys) do not trigger the agent's flush yet.

## Scale and overhead

- No rate limiting: every launch traps and unwinds. PyTorch-level launch
  rates (tens of thousands per second) would overflow `trace_events` and
  grow the correlator. Plan: rate-limit in the agent, only send completions
  for sampled launches.
- Held launch traces copy the full 24 KB frame buffer.
- Enable on attach: the agent's probes have no semaphore. Using
  `probe_lazy`-style semaphores and passing `SemaphoreOffset` as
  `UprobeOptions.RefCtrOffset` would make an idle agent nearly free.
- Kernel names are copied per event and truncated at 128 bytes; interning in
  the agent would remove both costs.

## Design cleanups

- `Match` uses the library file name; matching any mapping with
  `gpuprofiling` USDT notes would follow the contract instead.
- `tracer.loadAllMaps` hardcodes probe-owned map names (`sched_times`,
  `cuda_kernel_events`); probes could declare owned maps instead.
- `kernelEvent` mirrors `CudaKernelEvent` by hand; it could move to
  `support/types_def.go` and be generated.
- A generic USDT argument reader (per-site specs, memory and constant
  arguments) would serve this probe and memory profiling once 5.15 can be
  assumed or a cookie-free scheme is found.
- `probes/{cuda,kprobe,uprobe}/factory_others.go` reference
  `metadata.ExtensionsStability`, which does not exist
  (`ExtensionStability`); non-Linux builds of these extensions would fail
  (pre-existing in `kprobe` and `uprobe`, copied into `cuda`).

## Profile content

- Sample attributes for device, stream, context and graph IDs.
- Optionally trim the launch machinery between `cudaLaunchKernel` and the
  kernel leaf frame (CUPTI, driver and agent frames).
- Queueing delay (`kernel start - launch time`) as its own value or sample
  type, to show GPU contention between processes.
- `profile.frame.type = "cuda"` is not an OTel semantic convention value yet.

## Later phases

- PC sampling with stall reasons (CUPTI), cubins keyed by CRC for
  symbolization.
- Device metrics (NVML) as a separate collector receiver.
- Tests beyond the correlator unit tests: probe attach/detach and eBPF
  integration tests.

# References

- Agent: [rogercoll/cuda-gpu-profiling](https://github.com/rogercoll/cuda-gpu-profiling)
- Memory profiling USDT probes: PR #1746 and `design-docs/00003-memory-profiling`
- Parca's CUPTI agent: [parca-dev/parcagpu](https://github.com/parca-dev/parcagpu)
- CUPTI: [docs.nvidia.com/cupti](https://docs.nvidia.com/cupti/index.html)
