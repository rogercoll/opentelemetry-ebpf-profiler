//go:build ignore

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package support // import "go.opentelemetry.io/ebpf-profiler/support"

/*
#include "./ebpf/types.h"
#include "./ebpf/frametypes.h"
#include "./ebpf/v8_tracer.h"
*/
import "C"

const (
	FrameMarkerUnknown = C.FRAME_MARKER_UNKNOWN
	FrameMarkerPython  = C.FRAME_MARKER_PYTHON
	FrameMarkerNative  = C.FRAME_MARKER_NATIVE
	FrameMarkerPHP     = C.FRAME_MARKER_PHP
	FrameMarkerPHPJIT  = C.FRAME_MARKER_PHP_JIT
	FrameMarkerKernel  = C.FRAME_MARKER_KERNEL
	FrameMarkerHotSpot = C.FRAME_MARKER_HOTSPOT
	FrameMarkerRuby    = C.FRAME_MARKER_RUBY
	FrameMarkerPerl    = C.FRAME_MARKER_PERL
	FrameMarkerV8      = C.FRAME_MARKER_V8
	FrameMarkerDotnet  = C.FRAME_MARKER_DOTNET
	FrameMarkerBEAM    = C.FRAME_MARKER_BEAM
	FrameMarkerGo      = C.FRAME_MARKER_GO
)

const (
	FrameFlagError         = C.FRAME_FLAG_ERROR
	FrameFlagReturnAddress = C.FRAME_FLAG_RETURN_ADDRESS
	FrameFlagPidSpecific   = C.FRAME_FLAG_PID_SPECIFIC
)

const (
	ProgUnwindStop     = C.PROG_UNWIND_STOP
	ProgUnwindNative   = C.PROG_UNWIND_NATIVE
	ProgUnwindHotspot  = C.PROG_UNWIND_HOTSPOT
	ProgUnwindPython   = C.PROG_UNWIND_PYTHON
	ProgUnwindPHP      = C.PROG_UNWIND_PHP
	ProgUnwindRuby     = C.PROG_UNWIND_RUBY
	ProgUnwindPerl     = C.PROG_UNWIND_PERL
	ProgUnwindV8       = C.PROG_UNWIND_V8
	ProgUnwindDotnet   = C.PROG_UNWIND_DOTNET
	ProgUnwindDotnet10 = C.PROG_UNWIND_DOTNET10
	ProgGoLabels       = C.PROG_GO_LABELS
	ProgUnwindBEAM     = C.PROG_UNWIND_BEAM
)

const (
	DeltaCommandFlag = C.STACK_DELTA_COMMAND_FLAG

	MergeOpcodeNegative = C.MERGEOPCODE_NEGATIVE
)

const (
	EventTypeGenericPID     = C.EVENT_TYPE_GENERIC_PID
	EventTypeReloadKallsyms = C.EVENT_TYPE_RELOAD_KALLSYMS
)

const UnwindInfoMaxEntries = C.UNWIND_INFO_MAX_ENTRIES

const (
	MetricIDBeginCumulative = C.metricID_BeginCumulative
)

const (
	BitWidthPID  = C.BIT_WIDTH_PID
	BitWidthPage = C.BIT_WIDTH_PAGE
)

const (
	// StackDeltaBucket[Smallest|Largest] define the boundaries of the bucket sizes of the various
	// nested stack delta maps.
	StackDeltaBucketSmallest = C.STACK_DELTA_BUCKET_SMALLEST
	StackDeltaBucketLargest  = C.STACK_DELTA_BUCKET_LARGEST

	// StackDeltaPage[Bits|Mask] determine the paging size of stack delta map information
	StackDeltaPageBits = C.STACK_DELTA_PAGE_BITS
	StackDeltaPageMask = C.STACK_DELTA_PAGE_MASK
)

const (
	HSTSIDIsStubBit       = C.HS_TSID_IS_STUB_BIT
	HSTSIDHasFrameBit     = C.HS_TSID_HAS_FRAME_BIT
	HSTSIDStackDeltaBit   = C.HS_TSID_STACK_DELTA_BIT
	HSTSIDStackDeltaMask  = C.HS_TSID_STACK_DELTA_MASK
	HSTSIDStackDeltaScale = C.HS_TSID_STACK_DELTA_SCALE
	HSTSIDSegMapBit       = C.HS_TSID_SEG_MAP_BIT
	HSTSIDSegMapMask      = C.HS_TSID_SEG_MAP_MASK
)

const (
	TraceOriginUnknown  = C.TRACE_UNKNOWN
	TraceOriginSampling = C.TRACE_SAMPLING
	TraceOriginOffCPU   = C.TRACE_OFF_CPU
	TraceOriginProbe    = C.TRACE_PROBE
)

type ApmSpanID C.ApmSpanID
type ApmTraceID C.ApmTraceID
type CustomLabel C.CustomLabel
type CustomLabelsArray C.CustomLabelsArray
type Event C.Event
type OffsetRange C.OffsetRange
type PIDPage C.PIDPage
type PIDPageMappingInfo C.PIDPageMappingInfo
type StackDelta C.StackDelta
type StackDeltaPageInfo C.StackDeltaPageInfo
type StackDeltaPageKey C.StackDeltaPageKey
type SystemAnalysis C.SystemAnalysis
type TSDInfo C.TSDInfo
type DTVInfo C.DTVInfo
type Trace C.Trace
type UnwindInfo C.UnwindInfo

type ApmIntProcInfo C.ApmIntProcInfo
type BEAMProcInfo C.BEAMProcInfo
type DotnetProcInfo C.DotnetProcInfo
type GoLabelsOffsets C.GoLabelsOffsets
type HotspotProcInfo C.HotspotProcInfo
type PHPProcInfo C.PHPProcInfo
type PerlProcInfo C.PerlProcInfo
type PyProcInfo C.PyProcInfo
type RubyProcInfo C.RubyProcInfo
type V8ProcInfo C.V8ProcInfo

const (
	Sizeof_StackDelta = C.sizeof_StackDelta
	Sizeof_Trace      = C.sizeof_Trace

	sizeof_ApmIntProcInfo = C.sizeof_ApmIntProcInfo
	sizeof_DotnetProcInfo = C.sizeof_DotnetProcInfo
	sizeof_PHPProcInfo    = C.sizeof_PHPProcInfo
	sizeof_RubyProcInfo   = C.sizeof_RubyProcInfo
)

const (
	// Unwind register base values from the C header file
	UnwindRegInvalid uint8 = C.UNWIND_REG_INVALID
	UnwindRegCfa     uint8 = C.UNWIND_REG_CFA
	UnwindRegPc      uint8 = C.UNWIND_REG_PC
	UnwindRegSp      uint8 = C.UNWIND_REG_SP
	UnwindRegFp      uint8 = C.UNWIND_REG_FP
	UnwindRegLr      uint8 = C.UNWIND_REG_LR
	UnwindRegX86RAX  uint8 = C.UNWIND_REG_X86_RAX
	UnwindRegX86R9   uint8 = C.UNWIND_REG_X86_R9
	UnwindRegX86R11  uint8 = C.UNWIND_REG_X86_R11
	UnwindRegX86R15  uint8 = C.UNWIND_REG_X86_R15

	// UnwindFlag values from the C header file
	UnwindFlagCommand  uint8 = C.UNWIND_FLAG_COMMAND
	UnwindFlagFrame    uint8 = C.UNWIND_FLAG_FRAME
	UnwindFlagLeafOnly uint8 = C.UNWIND_FLAG_LEAF_ONLY
	UnwindFlagDerefCfa uint8 = C.UNWIND_FLAG_DEREF_CFA

	// UnwindCommands from the C header file
	UnwindCommandInvalid      int32 = C.UNWIND_COMMAND_INVALID
	UnwindCommandStop         int32 = C.UNWIND_COMMAND_STOP
	UnwindCommandPLT          int32 = C.UNWIND_COMMAND_PLT
	UnwindCommandSignal       int32 = C.UNWIND_COMMAND_SIGNAL
	UnwindCommandFramePointer int32 = C.UNWIND_COMMAND_FRAME_POINTER

	// UnwindDeref handling from the C header file
	UnwindDerefMask       int32 = C.UNWIND_DEREF_MASK
	UnwindDerefMultiplier int32 = C.UNWIND_DEREF_MULTIPLIER
)

const (
	// Hotspot specific
	FrameHotspotStub        = C.FRAME_HOTSPOT_STUB
	FrameHotspotVtable      = C.FRAME_HOTSPOT_VTABLE
	FrameHotspotInterpreter = C.FRAME_HOTSPOT_INTERPRETER
	FrameHotspotNative      = C.FRAME_HOTSPOT_NATIVE

	// V8 specific
	V8SmiTag            = C.V8_SmiTag
	V8SmiTagMask        = C.V8_SmiTagMask
	V8SmiTagShift       = C.V8_SmiTagShift
	V8SmiValueShift     = C.V8_SmiValueShift
	V8HeapObjectTag     = C.V8_HeapObjectTag
	V8HeapObjectTagMask = C.V8_HeapObjectTagMask

	V8FpContextSize = C.V8_FP_CONTEXT_SIZE

	V8FileTypeMarker       = C.V8_FILE_TYPE_MARKER
	V8FileTypeByteCode     = C.V8_FILE_TYPE_BYTECODE
	V8FileTypeNativeSFI    = C.V8_FILE_TYPE_NATIVE_SFI
	V8FileTypeNativeCode   = C.V8_FILE_TYPE_NATIVE_CODE
	V8FileTypeNativeJSFunc = C.V8_FILE_TYPE_NATIVE_JSFUNC
	V8FileTypeMask         = C.V8_FILE_TYPE_MASK

	V8LineCookieShift = C.V8_LINE_COOKIE_SHIFT
	V8LineCookieMask  = C.V8_LINE_COOKIE_MASK
	V8LineDeltaMask   = C.V8_LINE_DELTA_MASK

	RubyFrameTypeNone     = C.RUBY_FRAME_TYPE_NONE
	RubyFrameTypeCmeIseq  = C.RUBY_FRAME_TYPE_CME_ISEQ
	RubyFrameTypeCmeCfunc = C.RUBY_FRAME_TYPE_CME_CFUNC
	RubyFrameTypeIseq     = C.RUBY_FRAME_TYPE_ISEQ
	RubyFrameTypeGc       = C.RUBY_FRAME_TYPE_GC
)
