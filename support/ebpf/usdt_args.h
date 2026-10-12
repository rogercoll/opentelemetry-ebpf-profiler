// USDT arguments from the calling-convention registers. Producers must pin
// their probe arguments there (see cudaprofiling's probes.rs): reading the
// per-site spec from the SDT note would need bpf_get_attach_cookie (5.15).
#ifndef OPTI_USDT_ARGS_H
#define OPTI_USDT_ARGS_H

#if defined(__x86_64__)
  #define USDT_ARG0(ctx) ((ctx)->di)
  #define USDT_ARG1(ctx) ((ctx)->si)
  #define USDT_ARG2(ctx) ((ctx)->dx)
  #define USDT_ARG3(ctx) ((ctx)->cx)
  #define USDT_ARG4(ctx) ((ctx)->r8)
  #define USDT_ARG5(ctx) ((ctx)->r9)
#elif defined(__aarch64__)
  #define USDT_ARG0(ctx) ((ctx)->regs[0])
  #define USDT_ARG1(ctx) ((ctx)->regs[1])
  #define USDT_ARG2(ctx) ((ctx)->regs[2])
  #define USDT_ARG3(ctx) ((ctx)->regs[3])
  #define USDT_ARG4(ctx) ((ctx)->regs[4])
  #define USDT_ARG5(ctx) ((ctx)->regs[5])
#else
  #error "Unsupported architecture"
#endif

#endif
