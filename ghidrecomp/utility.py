import argparse
import multiprocessing
from pathlib import Path
from typing import Union, TYPE_CHECKING

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
    parser.add_argument('-o', '--output-path', help='Location for all decompilations', default='decompilations')

    group = parser.add_mutually_exclusive_group()
    group.add_argument('--sym-file-path', help='Specify single pdb symbol file for bin')
    group.add_argument('-s', '--symbols-path', help='Path for local symbols directory', default='.symbols')
    group.add_argument('--skip-symbols', help='Do not apply symbols', action='store_true')

    parser.add_argument('-t', '--thread-count', type=int,
                        help='Threads to use for processing. Defaults to cpu count', default=THREAD_COUNT)
    parser.add_argument('--va', help='Enable verbose analysis', action='store_true')

    return parser


def analyze_program(program, verbose: bool = False):
    # modified pyhidra.core._analyze_program

    print(f"Analyzing program {program.name}")

    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.program.util import GhidraProgramUtilities
    from ghidra.app.script import GhidraScriptUtil

    if verbose:
        print('Enabling verbose analysis..')
        monitor = ConsoleTaskMonitor()
        flat_api = FlatProgramAPI(program, monitor)
    else:
        flat_api = FlatProgramAPI(program)

    if GhidraProgramUtilities.shouldAskToAnalyze(program):
        GhidraScriptUtil.acquireBundleHostReference()
        try:
            flat_api.analyzeAll(program)
            GhidraProgramUtilities.setAnalyzedFlag(program, True)
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

    PdbUniversalAnalyzer.setAllowRemoteOption(program, True)
    PdbAnalyzer.setAllowRemoteOption(program, True)
