#include "bpfdefs.h"
#include "tracemgmt.h"

static EBPF_INLINE int unwind_ocaml(UNUSED void *ctx)
{
  printt("ocaml unimplemented unwinder called");
  return -1;
}

MULTI_USE_FUNC(unwind_ocaml)
