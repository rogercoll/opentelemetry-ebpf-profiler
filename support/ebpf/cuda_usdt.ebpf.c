// USDT handler for the "kernel" probe of the cudaprofiling agent: one event
// per GPU kernel record, sent to userspace without unwinding.

#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"
#include "usdt_args.h"

// Longest kernel name copied; longer (mangled C++) names are truncated
#define CUDA_KERNEL_NAME_LEN 128

// One kernel record. Mirrored by kernelEvent in probes/cuda.
typedef struct CudaKernelEvent {
  u64 correlation_id;
  u64 start; // CLOCK_MONOTONIC ns
  u64 end;
  u32 pid;
  u32 device_id;
  u32 stream_id;
  u32 pad;
  char name[CUDA_KERNEL_NAME_LEN];
} CudaKernelEvent;

// Kernel events for userspace, owned by the cuda probe
struct cuda_kernel_events_t {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} cuda_kernel_events SEC(".maps");

// kernel(correlation_id, start, end, device_id, stream_id, name)
SEC("kprobe/cuda_kernel")
int kprobe__cuda_kernel(struct pt_regs *ctx)
{
  u32 pid          = 0;
  u32 tid          = 0;
  u64 group_leader = 0;
  if (!get_pid_tgid_leader(&pid, &tid, &group_leader)) {
    return 0;
  }

  CudaKernelEvent event = {};
  event.pid             = pid;
  event.correlation_id  = USDT_ARG0(ctx);
  event.start           = USDT_ARG1(ctx);
  event.end             = USDT_ARG2(ctx);
  event.device_id       = (u32)USDT_ARG3(ctx);
  event.stream_id       = (u32)USDT_ARG4(ctx);
  // The name lives in CUPTI's record, valid while the probe fires
  bpf_probe_read_user_str(event.name, sizeof(event.name), (void *)USDT_ARG5(ctx));

  bpf_ringbuf_output(&cuda_kernel_events, &event, sizeof(event), 0);
  return 0;
}
