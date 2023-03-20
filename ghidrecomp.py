import argparse
from pathlib import Path
import multiprocessing
import concurrent.futures
from time import time
from typing import Union, TYPE_CHECKING
import json

import pyhidra

THREAD_COUNT = multiprocessing.cpu_count()

# needed for ghidra python vscode autocomplete
if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *


def setup_symbols(symbols_path: Union[str, Path]) -> None:
    """setup symbols to allow Ghidra to download as needed"""

    symbols_path = Path(symbols_path).absolute()

    from pdb_ import PdbPlugin
    from pdb_.symbolserver import LocalSymbolStore
    from pdb_.symbolserver import HttpSymbolServer
    from pdb_.symbolserver import SymbolServerService

    from java.util import List
    from java.io import File
    from java.net import URI

    # TODO support more than just Windows
    symbolsDir = File(symbols_path)
    localSymbolStore = LocalSymbolStore(symbols_path)

    # Creates a MS-compatible symbol server directory location. pdb/symbolserver/LocalSymbolStore.java#L67
    localSymbolStore.create(symbolsDir, 1)
    msSymbolServer = HttpSymbolServer(URI.create("https://msdl.microsoft.com/download/symbols/"))
    symbolServerService = SymbolServerService(localSymbolStore, List.of(msSymbolServer))

    PdbPlugin.saveSymbolServerServiceConfig(symbolServerService)


def get_pdb(prog: "ghidra.program.model.listing.Program") -> "java.io.File":
    """
    Searches the currently configured symbol server paths for a Pdb symbol file.
    """

    from pdb_.symbolserver import FindOption
    from ghidra.util.task import ConsoleTaskMonitor
    from pdb_ import PdbPlugin

    find_opts = FindOption.of(FindOption.ALLOW_REMOTE)
    # find_opts = FindOption.NO_OPTIONS

    # Ghidra/Features/PDB/src/main/java/pdb/PdbPlugin.java#L191
    pdb = PdbPlugin.findPdb(prog, find_opts, ConsoleTaskMonitor())

    return pdb


def set_pdb(program: "ghidra.program.model.listing.Program", path: Union[str, Path]):

    from ghidra.app.plugin.core.analysis import PdbUniversalAnalyzer
    from java.io import File

    symbol_path = Path(symbol_path)
    print(f'Setting pdb to {symbol_path}')

    pdbFile = File(symbol_path)
    PdbUniversalAnalyzer.setPdbFileOption(program, pdbFile)


def setup_decompliers(p1: "ghidra.program.model.listing.Program") -> dict:
    """
    Setup decompliers to use during diff bins. Each one must be initialized with a program.
    """

    from ghidra.app.decompiler import DecompInterface

    decompilers = {}

    for i in range(THREAD_COUNT):
        decompilers.setdefault(i, DecompInterface())
        decompilers[i].openProgram(p1)

    print(f'Setup {THREAD_COUNT} decompliers')

    return decompilers


def decompile_func(func: 'ghidra.program.model.listing.Function', monitor, decompilers: dict, thread_id: int = 0, TIMEOUT: int = 1) -> list:
    """
    Decompile function and return [funcname, decompilation]
    Ghidra/Features/Decompiler/src/main/java/ghidra/app/util/exporter/CppExporter.java#L514
    """
    MAX_PATH_LEN = 50
    decomp = decompilers[thread_id].decompileFunction(func, TIMEOUT, monitor).getDecompiledFunction()
    code = decomp.getC() if decomp else ""

    return [f'{func.getName()[:MAX_PATH_LEN]}-{func.iD}', code]


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='ghidrecomp - A Command Line Ghidra Decompiler',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('bin', help='Path to binary used for analysis')
    parser.add_argument('-s', '--symbol-path', help='Path to symbol path for bin', default='.symbols')
    parser.add_argument('--sym-file-path', help='Specify pdb symbol file for bin')
    parser.add_argument('-o', '--output-path', help='Location for all decompilations', default='decompilations')
    parser.add_argument('--project-path', help='Path to base ghidra projects ', default='.ghidra_projects')

    args = parser.parse_args()

    print(args)

    bin_path = Path(args.bin)
    project_location = Path(args.project_path)

    output_path = Path(args.output_path) / bin_path.name
    output_path.mkdir(exist_ok=True, parents=True)

    # need to start pyhidra to activate Java and Jpype
    pyhidra.start(True)

    from ghidra.util.task import ConsoleTaskMonitor

    monitor = ConsoleTaskMonitor()

    with pyhidra.open_program(bin_path, project_location=project_location, project_name=bin_path.name, analyze=False) as flat_api:

        from ghidra.program.util import GhidraProgramUtilities
        from ghidra.app.script import GhidraScriptUtil

        program: "ghidra.program.model.listing.Program" = flat_api.getCurrentProgram()

        if args.sym_file_path:
            set_pdb(program, args.sym_file_path)

        elif 'visualstudio' in program.compiler:

            # configure windows symbol path for bin
            setup_symbols(args.symbol_path)

            from ghidra.app.plugin.core.analysis import PdbAnalyzer
            from ghidra.app.plugin.core.analysis import PdbUniversalAnalyzer
            # Enable Remote Symbol Servers
            PdbUniversalAnalyzer.setAllowRemoteOption(program, True)
            PdbAnalyzer.setAllowRemoteOption(program, True)

            pdb = get_pdb(program)
            # assert pdb is not None

        decompilers = setup_decompliers(program)

        # analyze program if we haven't yet
        # if GhidraProgramUtilities.shouldAskToAnalyze(program):
        # GhidraScriptUtil.acquireBundleHostReference()
        # #flat_api.analyzeAll(program)
        # GhidraProgramUtilities.setAnalyzedFlag(program, True)
        # GhidraScriptUtil.releaseBundleHostReference()

        all_funcs = []
        skip_count = 0

        for f in program.functionManager.getFunctions(True):

            # if f.getName().startswith('FUN_'):
            #     # skip FUN for demo
            #     skip_count += 1
            #     continue

            all_funcs.append(f)
        print(f'Skipped {skip_count} FUN_ functions')
        print(f'Decompiling {len(all_funcs)} functions using {THREAD_COUNT} threads')

        from decompiler import MyDecompileConfigurer
        from ghidra.app.decompiler.parallel import ParallelDecompiler
        from ghidra.app.decompiler.parallel import DecompilerCallback
        from ghidra.app.decompiler.parallel import DecompileConfigurer
        from decompiler import CallBack
        from ghidra.app.plugin.core.decompile import DecompilePlugin, DecompilerProvider

        plugin =
        DecompilerProvider()

        # import ghidra.app.util
        from ghidra.app.util.exporter import CppExporter

        # configurer = MyDecompileConfigurer()
        # callback = DecompilerCallback(program, configurer)

        # callback = CallBack()

        # ParallelDecompiler.decompileFunctions(callback, program, all_funcs, None, monitor)

        from java.io import File

        test = File('test')

        start = time()
        decompiler = CppExporter(True, True, True, False, None)
        decompiler.export(test, program, program.getMemory(), ConsoleTaskMonitor.DUMMY)
        print(f'Wrote for {program.name} to {output_path} in {time() - start}')

        completed = 0
        decompilations = []
        start = time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
            futures = (executor.submit(decompile_func, func, monitor, decompilers, thread_id % THREAD_COUNT)
                       for thread_id, func in enumerate(all_funcs))
            for future in concurrent.futures.as_completed(futures):
                decompilations.append(future.result())
                completed += 1
                if (completed % 100) == 0:
                    print(f'Completed {completed} and {int(completed/len(all_funcs)*100)}%')

        print(f'Decompiled {completed} functions for {program.name} in {time() - start}')

        start = time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
            futures = (executor.submit((output_path / (name + '.c')).write_text, decomp)
                       for name, decomp in decompilations)
            for future in concurrent.futures.as_completed(futures):
                decompilations.append(future.result())

        print(f'Wrote {completed} decompilations for {program.name} to {output_path} in {time() - start}')
