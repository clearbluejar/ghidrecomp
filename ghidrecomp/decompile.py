import re
from pathlib import Path
from typing import TYPE_CHECKING
from argparse import Namespace
import concurrent.futures
from time import time
import pyhidra

from .utility import set_pdb, setup_symbol_server, set_remote_pdbs, analyze_program

# needed for ghidra python vscode autocomplete
if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *


def setup_decompliers(program: "ghidra.program.model.listing.Program", thread_count: int = 2) -> dict:
    """
    Setup decompliers to use during diff bins. Each one must be initialized with a program.
    """

    from ghidra.app.decompiler import DecompInterface

    decompilers = {}

    for i in range(thread_count):
        decompilers.setdefault(i, DecompInterface())
        decompilers[i].openProgram(program)

    print(f'Setup {thread_count} decompliers')

    return decompilers


def decompile_func(func: 'ghidra.program.model.listing.Function',
                   decompilers: dict,
                   thread_id: int = 0,
                   TIMEOUT: int = 0,
                   monitor=None) -> list:
    """
    Decompile function and return [funcname, decompilation]
    Ghidra/Features/Decompiler/src/main/java/ghidra/app/util/exporter/CppExporter.java#L514
    """
    MAX_PATH_LEN = 50
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.app.decompiler import DecompiledFunction, DecompileResults

    if monitor is None:
        monitor = ConsoleTaskMonitor()

    result: "DecompileResults" = decompilers[thread_id].decompileFunction(func, TIMEOUT, monitor)

    if '' == result.errorMessage:
        code = result.decompiledFunction.getC()
        sig = result.decompiledFunction.getSignature()
    else:
        code = result.errorMessage
        sig = None

    return [f'{func.getName()[:MAX_PATH_LEN]}-{func.entryPoint}', code, sig]


def decompile_to_single_file(path: Path,
                             prog: "ghidra.program.model.listing.Program",
                             create_header: bool = True,
                             createFile: bool = True,
                             emit_types: bool = True,
                             excludeTags: bool = True,
                             tags: str = None,
                             verbose: bool = True):
    """
    Use Ghidra's CppExporter to decompile all functions to a single file
    """
    from ghidra.app.util.exporter import CppExporter
    from ghidra.util.task import ConsoleTaskMonitor
    from java.io import File

    c_file = File(path.absolute())

    if verbose:
        monitor = ConsoleTaskMonitor()
    else:
        monitor = ConsoleTaskMonitor().DUMMY

    decompiler = CppExporter(True, True, True, False, None)
    decompiler.export(c_file, prog, prog.getMemory(), monitor)


def decompile(args: Namespace):

    print(f'Starting decompliations: {args}')

    bin_path = Path(args.bin)
    project_location = Path(args.project_path)
    thread_count = args.thread_count

    output_path = Path(args.output_path) / bin_path.name
    output_path.mkdir(exist_ok=True, parents=True)

    # turn on verbose
    pyhidra.start(True)

    with pyhidra.open_program(bin_path, project_location=project_location, project_name=bin_path.name, analyze=False) as flat_api:

        from ghidra.util.task import ConsoleTaskMonitor
        from ghidra.program.model.listing import Program
        monitor = ConsoleTaskMonitor()

        program: "Program" = flat_api.getCurrentProgram()

        if not args.skip_symbols:
            if args.sym_file_path:
                set_pdb(program, args.sym_file_path)
            else:
                setup_symbol_server(args.symbols_path)

                set_remote_pdbs(program, True)

                # pdb = get_pdb(program)
                # assert pdb is not None

        # analyze program if we haven't yet
        analyze_program(program, verbose=args.va)

        all_funcs = []
        skip_count = 0

        for f in program.functionManager.getFunctions(True):

            if args.filters:
                if any([re.search(fil, f.name, re.IGNORECASE) for fil in args.filters]):
                    all_funcs.append(f)
                else:
                    skip_count += 1
            else:
                all_funcs.append(f)

        print(f'Skipped {skip_count} functions that failed to match any of {args.filters}')

        if args.cppexport:
            print(f"Decompiling {len(all_funcs)} functions using Ghidra's CppExporter")
            c_file = Path(args.output_path) / Path(bin_path.name + '.c')
            start = time()
            decompile_to_single_file(c_file, program)
            print(f'Decompiled {len(all_funcs)} functions for {program.name} in {time() - start}')
            print(f"Wrote results to {c_file} and {c_file.stem + '.h'}")
        else:
            print(f'Decompiling {len(all_funcs)} functions using {thread_count} threads')

            decompilers = setup_decompliers(program, thread_count)

            completed = 0
            decompilations = []
            start = time()
            with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
                futures = (executor.submit(decompile_func, func, decompilers, thread_id % thread_count, monitor=monitor)
                           for thread_id, func in enumerate(all_funcs))

                for future in concurrent.futures.as_completed(futures):
                    decompilations.append(future.result())
                    completed += 1
                    if (completed % 100) == 0:
                        print(f'Completed {completed} and {int(completed/len(all_funcs)*100)}%')

            print(f'Decompiled {completed} functions for {program.name} in {time() - start}')

            start = time()
            with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
                futures = (executor.submit((output_path / (name + '.c')).write_text, decomp)
                           for name, decomp, sig in decompilations)

                for future in concurrent.futures.as_completed(futures):
                    pass

            print(f'Wrote {completed} decompilations for {program.name} to {output_path} in {time() - start}')

            return (all_funcs, decompilations, output_path, str(program.compiler), str(program.languageID))
