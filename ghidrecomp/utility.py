import argparse
import multiprocessing
from pathlib import Path
from typing import Union, TYPE_CHECKING
from pyhidra import launcher

from ghidrecomp import __version__

THREAD_COUNT = multiprocessing.cpu_count()

# needed for ghidra python vscode autocomplete
if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *  # noqa: F403


def get_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(description='ghidrecomp - A Command Line Ghidra Decompiler',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('bin', help='Path to binary used for analysis')
    parser.add_argument('--cppexport', action='store_true', help='Use Ghidras CppExporter to decompile to single file')
    parser.add_argument('--filter', dest='filters', action='append', help='Regex match for function name')
    parser.add_argument('--project-path', help='Path to base ghidra projects ', default='.ghidra_projects')
    parser.add_argument('--gdt', help='Additional GDT to apply', nargs='?', action='append')
    parser.add_argument('-o', '--output-path', help='Location for all decompilations', default='decompilations')
    parser.add_argument("-v", "--version", action="version", version=__version__)
    parser.add_argument("--skip-cache", action='store_true',
                        help='Skip cached and genearate new decomp and callgraphs.')

    group = parser.add_mutually_exclusive_group()
    group.add_argument('--sym-file-path', help='Specify single pdb symbol file for bin')
    group.add_argument('-s', '--symbols-path', help='Path for local symbols directory', default='.symbols')
    group.add_argument('--skip-symbols', help='Do not apply symbols', action='store_true')

    parser.add_argument('-t', '--thread-count', type=int,
                        help='Threads to use for processing. Defaults to cpu count', default=THREAD_COUNT)
    parser.add_argument('--va', help='Enable verbose analysis', action='store_true')
    parser.add_argument('--fa', help='Force new analysis (even if already analyzed)', action='store_true')

    group = parser.add_argument_group('JVM Options')
    group.add_argument('--max-ram-percent', help='Set JVM Max Ram %% of host RAM', default=50.0)
    group.add_argument('--print-flags', help='Print JVM flags at start', action='store_true')

    group = parser.add_argument_group('Callgraph Options')
    group.add_argument('--callgraphs',  help='Generate callgraph markdown', action='store_true')
    group.add_argument('--callgraph-filter',
                       help='Only generate callgraphs for functions matching filter', default='.')
    group.add_argument('--mdd', '--max-display-depth', help='Max Depth for graph generation', dest='max_display_depth')
    group.add_argument('--max-time-cg-gen', help='Max time in seconds to wait for callgraph gen.', default=5)
    group.add_argument('--cg-direction', help='Direction for callgraph.',
                       choices=['calling', 'called', 'both'], default='calling')

    return parser


def analyze_program(program, verbose: bool = False, force_analysis: bool = False, save: bool = False):
    """
    Modified pyhidra.core._analyze_program    
    """

    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.program.util import GhidraProgramUtilities
    from ghidra.app.script import GhidraScriptUtil

    if verbose:
        print('Enabling verbose analysis...')
        monitor = ConsoleTaskMonitor()
        flat_api = FlatProgramAPI(program, monitor)
    else:
        flat_api = FlatProgramAPI(program)

    if GhidraProgramUtilities.shouldAskToAnalyze(program) or force_analysis:
        print(f"Analyzing program {program.name}...")

        GhidraScriptUtil.acquireBundleHostReference()
        try:
            print(f"Running analyzers...")
            flat_api.analyzeAll(program)
            if hasattr(GhidraProgramUtilities, 'setAnalyzedFlag'):
                GhidraProgramUtilities.setAnalyzedFlag(program, True)
            elif hasattr(GhidraProgramUtilities, 'markProgramAnalyzed'):
                GhidraProgramUtilities.markProgramAnalyzed(program)
            else:
                raise Exception('Missing set analyzed flag method!')

            if save:
                flat_api.saveProgram(program)
        finally:
            GhidraScriptUtil.releaseBundleHostReference()
    else:
        print(f'{program} already analyzed... skipping')


def setup_symbol_server(symbols_path: Union[str, Path], level=1, server_urls=None) -> None:
    """
    setup symbols to allow Ghidra to download as needed
    1. Configures symbol_path as local symbol store path
    2. Sets Index level for local symbol path
    - Level 0 indexLevel is a special Ghidra construct - plain directory with a collection of Pdb files
    - Level 1, with pdb files stored directly underthe root directory
    - Level 2, using the first 2 characters of the pdb filename as a bucket to place each pdb file-directory in
    [symbol-store-folder-tree](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/symbol-store-folder-tree)
    """

    from pdb_ import PdbPlugin
    from pdb_.symbolserver import LocalSymbolStore
    from pdb_.symbolserver import HttpSymbolServer
    from pdb_.symbolserver import SymbolServerService
    from ghidra.framework import Application

    from java.io import File
    from java.net import URI
    from java.util import ArrayList

    print("Setting up Symbol Server for symbols...")
    print(f"path: {symbols_path} level: {level}")

    symbols_path = Path(symbols_path).absolute()

    # Configure local symbols directory
    symbolsDir = File(symbols_path)
    localSymbolStore = LocalSymbolStore(symbols_path)

    # Create local symbol server
    # pdb/symbolserver/LocalSymbolStore.java#L67
    localSymbolStore.create(symbolsDir, level)

    # Configure well known symbol urls
    if server_urls is None:
        # load wellknown servers
        # Ghidra/Features/PDB/src/main/java/pdb/symbolserver/ui/WellKnownSymbolServerLocation.java#L89
        known_urls = []
        pdbUrlFiles = Application.findFilesByExtensionInApplication(".pdburl")
        for pdbFile in pdbUrlFiles:
            data = Path(pdbFile.absolutePath).read_text()
            print(f"Loaded well known {pdbFile.absolutePath}' length: {len(data)}'")
            for line in data.splitlines(True):
                cat, location, warning = line.split('|')
                known_urls.append(location)
        server_urls = known_urls
    else:
        if not isinstance(server_urls, list):
            raise TypeError('server_urls must be a list of urls')

    symServers = ArrayList()

    for url in server_urls:
        symServers.add(HttpSymbolServer(URI.create(url)))

    symbolServerService = SymbolServerService(localSymbolStore, symServers)

    PdbPlugin.saveSymbolServerServiceConfig(symbolServerService)

    print(f'Symbol Server Configured path: {symbolServerService.toString().strip()}')


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

    print(f'Setting pdb to {symbol_path}')
    symbol_path = Path(path)
    pdbFile = File(symbol_path)
    PdbUniversalAnalyzer.setPdbFileOption(program, pdbFile)


def set_remote_pdbs(program: "ghidra.program.model.listing.Program", allow: bool):
    """
    Enable or disable remote PDB downloads
    """

    from ghidra.app.plugin.core.analysis import PdbAnalyzer
    from ghidra.app.plugin.core.analysis import PdbUniversalAnalyzer
    # Enable Remote Symbol Servers

    PdbUniversalAnalyzer.setAllowRemoteOption(program, allow)
    PdbAnalyzer.setAllowRemoteOption(program, allow)


def apply_gdt(program: "ghidra.program.model.listing.Program", gdt_path:  Union[str, Path], verbose: bool = False):
    """
    Apply GDT to program
    """

    from ghidra.app.cmd.function import ApplyFunctionDataTypesCmd
    from ghidra.program.model.symbol import SourceType
    from java.io import File
    from java.util import List
    from ghidra.program.model.data import FileDataTypeManager
    from ghidra.util.task import ConsoleTaskMonitor

    gdt_path = Path(gdt_path)

    if verbose:
        print('Enabling verbose gdt..')
        monitor = ConsoleTaskMonitor()
    else:
        monitor = ConsoleTaskMonitor().DUMMY_MONITOR

    archiveGDT = File(gdt_path)
    archiveDTM = FileDataTypeManager.openFileArchive(archiveGDT, False)
    always_replace = True
    createBookmarksEnabled = True
    cmd = ApplyFunctionDataTypesCmd(List.of(archiveDTM), None, SourceType.USER_DEFINED,
                                    always_replace, createBookmarksEnabled)
    cmd.applyTo(program, monitor)
