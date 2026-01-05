package ocaml

import (
	"fmt"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
)

func Loader(ebpf interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}

	// internal function in the OCaml runtime that sets up and starts
	// execution of a compiled OCaml program.
	_, ocamlVersion, err := ef.SymbolData("caml_start_program", 1)
	if err != nil {
		// If the symbol isn't found, this isn't a native OCaml binary we can unwind.
		return nil, nil
	}
	log.Warn(fmt.Sprintf("Detected an Ocaml binary with version: %s", ocamlVersion))
	return nil, nil
}
