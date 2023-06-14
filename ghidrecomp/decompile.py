import re
from pathlib import Path
from typing import TYPE_CHECKING
from argparse import Namespace
import concurrent.futures
from time import time
import json
from pyhidra import HeadlessPyhidraLauncher, open_program

from .utility import set_pdb, setup_symbol_server, set_remote_pdbs, analyze_program, get_pdb, apply_gdt
from .callgraph import get_called, get_calling, CallGraph

# needed for ghidra python vscode autocomplete
if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *

MAX_PATH_LEN = 50


def get_filename(func: 'ghidra.program.model.listing.Function'):
    return f'{func.getName()[:MAX_PATH_LEN]}-{func.entryPoint}'


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
                   timeout: int = 0,
                   monitor=None) -> list:
    """
    Decompile function and return [funcname, decompilation]
    Ghidra/Features/Decompiler/src/main/java/ghidra/app/util/exporter/CppExporter.java#L514
    """
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.app.decompiler import DecompiledFunction, DecompileResults

    if monitor is None:
        monitor = ConsoleTaskMonitor()

    result: "DecompileResults" = decompilers[thread_id].decompileFunction(func, timeout, monitor)

    if '' == result.getErrorMessage():
        code = result.decompiledFunction.getC()
        sig = result.decompiledFunction.getSignature()
    else:
        code = result.getErrorMessage()
        sig = None

    return [get_filename(func), code, sig]


def decompile_to_single_file(path: Path,
                             prog: "ghidra.program.model.listing.Program",
                             create_header: bool = True,
                             create_file: bool = True,
                             emit_types: bool = True,
                             exclude_tags: bool = False,
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

    decompiler = CppExporter(create_header, create_file, emit_types, exclude_tags, tags)
    decompiler.export(c_file, prog, prog.getMemory(), monitor)


def gen_callgraph(func: 'ghidra.program.model.listing.Function', max_display_depth=None, direction='calling', max_run_time=None):

    name = get_filename(func)
    # print(f'Generating {direction} callgraph for : {name}')
    flow = ''
    callgraph = None

    try:
        if direction == 'calling':
            callgraph = get_calling(func, max_run_time=max_run_time)
        elif direction == 'called':
            callgraph = get_called(func, max_run_time=max_run_time)
        else:
            raise Exception(f'Unsupported callgraph direction {direction}')

    except TimeoutError as error:
        flow = flow_ends = mind = f'\nError: {error} func: {func.name}. max_run_time: {max_run_time} Increase timeout with --max-time-cg-gen MAX_TIME_CG_GEN'
        print(flow)

    if callgraph is not None:
        flow = callgraph.gen_mermaid_flow_graph(
            shaded_nodes=callgraph.get_endpoints(),
            max_display_depth=max_display_depth,
            wrap_mermaid=True)
        flow_ends = callgraph.gen_mermaid_flow_graph(
            shaded_nodes=callgraph.get_endpoints(), endpoint_only=True, wrap_mermaid=True)
        mind = callgraph.gen_mermaid_mind_map(max_display_depth=3, wrap_mermaid=True)

    return [name, direction, callgraph, [['flow', flow], ['flow_ends', flow_ends], ['mind', mind]]]


def decompile(args: Namespace):

    print(f'Starting decompliations: {args}')

    bin_path = Path(args.bin)
    project_location = Path(args.project_path)
    thread_count = args.thread_count

    output_path = Path(args.output_path) / bin_path.name
    output_path.mkdir(exist_ok=True, parents=True)

    # turn on verbose
    launcher = HeadlessPyhidraLauncher(True)

    # set max % of host RAM
    launcher.add_vmargs(f'-XX:MaxRAMPercentage={args.max_ram_percent}')
    if args.print_flags:
        launcher.add_vmargs('-XX:+PrintFlagsFinal')

    launcher.start()

    from ghidra.util.task import ConsoleTaskMonitor
    monitor = ConsoleTaskMonitor()
    from ghidra.program.model.listing import Program

    # Setup and analyze project
    with open_program(bin_path, project_location=project_location, project_name=bin_path.name, analyze=False) as flat_api:

        program: "Program" = flat_api.getCurrentProgram()

        if not args.skip_symbols:
            if args.sym_file_path:
                set_pdb(program, args.sym_file_path)
            else:
                setup_symbol_server(args.symbols_path)

                set_remote_pdbs(program, True)

            pdb = get_pdb(program)
            if pdb is None:
                print(f"Failed to find pdb for {program}")

        # apply GDT
        if args.gdt:
            for gdt_path in args.gdt:
                print(f'Applying gdt {gdt_path}...')
                apply_gdt(program, gdt_path, verbose=args.va)

        gdt_names = [name for name in program.getDataTypeManager().getSourceArchives()]
        if len(gdt_names) > 0:
            print(f'Using file gdts: {gdt_names}')

        # analyze program if we haven't yet
        analyze_program(program, verbose=args.va, force_analysis=args.fa)

    # decompile and callgraph all the things
    with open_program(bin_path, project_location=project_location, project_name=bin_path.name, analyze=False) as flat_api:

        all_funcs = []
        skip_count = 0

        program: "Program" = flat_api.getCurrentProgram()

        for f in program.functionManager.getFunctions(True):

            if args.filters:
                if any([re.search(fil, f.name, re.IGNORECASE) for fil in args.filters]):
                    all_funcs.append(f)
                else:
                    skip_count += 1
            else:
                all_funcs.append(f)

        if skip_count > 0:
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
            callgraphs = []

            # Decompile all files
            start = time()
            with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
                futures = (executor.submit(decompile_func, func, decompilers, thread_id % thread_count, monitor=monitor)
                           for thread_id, func in enumerate(all_funcs) if args.skip_cache or not (output_path / (get_filename(func) + '.c')).exists())

                for future in concurrent.futures.as_completed(futures):
                    decompilations.append(future.result())
                    completed += 1
                    if (completed % 100) == 0:
                        print(f'Decompiled {completed} and {int(completed/len(all_funcs)*100)}%')

            print(f'Decompiled {completed} functions for {program.name} in {time() - start}')
            print(f'{len(all_funcs) - completed} decompilations already existed.')

            # Save all decomps
            start = time()
            with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
                futures = (executor.submit((output_path / (name + '.c')).write_text, decomp)
                           for name, decomp, sig in decompilations)

                for future in concurrent.futures.as_completed(futures):
                    pass

            print(f'Wrote {completed} decompilations for {program.name} to {output_path} in {time() - start}')

            # Generate callgrpahs for functions
            if args.callgraphs:

                start = time()
                completed = 0
                callgraph_path = output_path / 'callgraphs'
                callgraphs_completed_path = callgraph_path / 'completed_callgraphs.json'
                if callgraphs_completed_path.exists():
                    callgraphs_completed = json.loads(callgraphs_completed_path.read_text())
                else:
                    callgraphs_completed = []

                callgraph_path.mkdir(exist_ok=True)

                if args.cg_direction == 'both':
                    directions = ['called', 'calling']
                else:
                    directions = [args.cg_direction]

                with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
                    futures = (executor.submit(gen_callgraph, func, args.max_display_depth, direction, args.max_time_cg_gen)
                               for direction in directions for func in all_funcs if args.skip_cache or get_filename(func) not in callgraphs_completed and re.search(args.callgraph_filter, func.name) is not None)

                    for future in concurrent.futures.as_completed(futures):

                        callgraphs.append(future.result())
                        name, direction, callgraph, graphs = callgraphs[-1]

                        for ctype, chart in graphs:
                            (callgraph_path / (name + f'.{ctype}.{direction}.md')).write_text(chart)
                        callgraphs_completed.append(name)

                        completed += 1
                        if (completed % 100) == 0:
                            per_complete = int(completed/len(all_funcs)*100*len(directions))
                            print(f'\nGenerated callgraph {completed} and {per_complete}%\n')

                callgraphs_completed_path.write_text(json.dumps(callgraphs_completed))
                print(f'Callgraphed {completed} functions for {program.name} in {time() - start}')
                print(f'Wrote {completed} callgraphs for {program.name} to {callgraph_path} in {time() - start}')
                print(f'{len(all_funcs) - completed} callgraphs already existed.')

        return (all_funcs, decompilations, output_path, str(program.compiler), str(program.languageID), callgraphs)
