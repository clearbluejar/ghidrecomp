import re
from pathlib import Path
from typing import TYPE_CHECKING
from argparse import Namespace
import concurrent.futures
from time import time
import json
import hashlib
from pyhidra import HeadlessPyhidraLauncher, open_program

from .utility import set_pdb, setup_symbol_server, set_remote_pdbs, analyze_program, get_pdb, apply_gdt
from .callgraph import get_called, get_calling, CallGraph, gen_callgraph
from .bsim import gen_bsim_sigs_for_program,has_bsim

# needed for ghidra python vscode autocomplete
if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *

MAX_PATH_LEN = 50


def get_filename(func: 'ghidra.program.model.listing.Function'):
    return f'{func.getName()[:MAX_PATH_LEN]}-{func.entryPoint}'

def get_md5_file_digest(path: str) -> str:
    # https://stackoverflow.com/questions/22058048/hashing-a-file-in-python
    # BUF_SIZE is totally arbitrary, change for your app!
    BUF_SIZE = 65536  # lets read stuff in 64kb chunks!

    path = Path(path)

    md5 = hashlib.md5()

    with path.open('rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            md5.update(data)

    return f'{md5.hexdigest()}'

def gen_proj_bin_name_from_path(path: Path):
    """
    Generate unique project name from binary for Ghidra Project
    """

    return '-'.join((path.name, get_md5_file_digest(path.absolute())))

def get_bin_output_path(output_path: Path, bin_name: str):

    return Path(output_path) / 'bins' / bin_name

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

    try:
        # Ghidra CppExporter before 10.3.3 and later        
        decompiler = CppExporter(None,create_header, create_file, emit_types, exclude_tags, tags)
    except TypeError:
        # Ghidra CppExporter before 10.3.3
        decompiler = CppExporter(create_header, create_file, emit_types, exclude_tags, tags)

    decompiler.export(c_file, prog, prog.getMemory(), monitor)



def decompile(args: Namespace):

    print(f'Starting decompliations: {args}')

    bin_path = Path(args.bin)
    bin_proj_name = gen_proj_bin_name_from_path(bin_path) 
    thread_count = args.thread_count

    output_path = Path(args.output_path)
    bin_output_path = get_bin_output_path(output_path, bin_proj_name) 
    decomp_path = bin_output_path / 'decomps'
    output_path.mkdir(exist_ok=True, parents=True)
    bin_output_path.mkdir(exist_ok=True, parents=True)
    decomp_path.mkdir(exist_ok=True, parents=True)
    

    if args.project_path == 'ghidra_projects':
        project_location = output_path / args.project_path
    else:
        project_location = Path(args.project_path)

    if args.symbols_path == 'symbols':
        symbols_path = output_path / args.symbols_path
    else:
        symbols_path = Path(args.symbols_path)

    if args.bsim_sig_path == 'bsim_xmls':
        bsim_sig_path = output_path / args.bsim_sig_path
    else:
        bsim_sig_path = output_path / Path(args.bsim_sig_path)


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
    with open_program(bin_path, project_location=project_location, project_name=bin_proj_name, analyze=False) as flat_api:

        program: "Program" = flat_api.getCurrentProgram()

        if not args.skip_symbols:
            if args.sym_file_path:
                set_pdb(program, args.sym_file_path)
            else:
                setup_symbol_server(symbols_path)

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
    with open_program(bin_path, project_location=project_location, project_name=bin_proj_name, analyze=False) as flat_api:

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

        decompilations = []
        callgraphs = []

        if args.cppexport:
            print(f"Decompiling {len(all_funcs)} functions using Ghidra's CppExporter")
            c_file = decomp_path / Path(bin_path.name + '.c')
            start = time()
            decompile_to_single_file(c_file, program)
            print(f'Decompiled {len(all_funcs)} functions for {program.name} in {time() - start}')
            print(f"Wrote results to {c_file} and {c_file.stem + '.h'}")
        else:
            print(f'Decompiling {len(all_funcs)} functions using {thread_count} threads')

            decompilers = setup_decompliers(program, thread_count)
            completed = 0

            # Decompile all files
            start = time()
            with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
                futures = (executor.submit(decompile_func, func, decompilers, thread_id % thread_count, monitor=monitor)
                           for thread_id, func in enumerate(all_funcs) if args.skip_cache or not (decomp_path / (get_filename(func) + '.c')).exists())

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
                futures = (executor.submit((decomp_path / (name + '.c')).write_text, decomp)
                           for name, decomp, sig in decompilations)

                for future in concurrent.futures.as_completed(futures):
                    pass

            print(f'Wrote {completed} decompilations for {program.name} to {decomp_path} in {time() - start}')

            # Generate callgrpahs for functions
            if args.callgraphs:

                start = time()
                completed = 0
                callgraph_path = bin_output_path / 'callgraphs'
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

                max_display_depth = None
                if args.max_display_depth is not None:
                    max_display_depth = int(args.max_display_depth)
                    
                with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
                    futures = (executor.submit(gen_callgraph, func, max_display_depth, direction, args.max_time_cg_gen, get_filename(func))
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


        # BSim
        gensig = None
        manager = None
        if args.bsim:
            
            if has_bsim():
                start = time()
                print(f'Generating BSim sigs for {len(all_funcs)} functions for {program.name}')
                sig_name, func_count, cat_count = gen_bsim_sigs_for_program(program,bsim_sig_path,args.bsim_template,args.bsim_cat,all_funcs)
                print(f'Generated BSim sigs for {func_count} functions in {time() - start}')
                print(f'Sigs are in {bsim_sig_path / sig_name}')
            else:
                print('WARN: Skipping BSim. BSim not present')
                   
        
        return (all_funcs, decompilations, bin_output_path, str(program.compiler), str(program.languageID), callgraphs)
