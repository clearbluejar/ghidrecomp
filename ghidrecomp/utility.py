from pathlib import Path
from typing import Union, TYPE_CHECKING

# needed for ghidra python vscode autocomplete
if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *


def analyze_program(program, verbose: bool = False):
    # modified pyhidra.core._analyze_program

    print(f"Analyzing program {program.name}")

    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.program.util import GhidraProgramUtilities
    from ghidra.app.script import GhidraScriptUtil

    if verbose:
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


def setup_symbol_server(symbols_path: Union[str, Path], level=1, server_urls=None) -> None:
    """setup symbols to allow Ghidra to download as needed
    1. Configures symbol_path as local symbol store path
    2. Sets Index level for local symbol path                 
    - Level 0 indexLevel is a special Ghidra construct that is just a user-friendlier plain directory with a collection of Pdb files
    [symbol-store-folder-tree](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/symbol-store-folder-tree) (applies to 1 and 2)
    - Level 1, with pdb files stored directly underthe root directory
    - Level 2, using the first 2 characters of the pdb filename as a bucket to place each pdb file-directory in        
    """

    print("Setting up Symbol Server for symbols...")
    print(f"path: {symbols_path} level: {level}")

    symbols_path = Path(symbols_path).absolute()

    from pdb_ import PdbPlugin
    from pdb_.symbolserver import LocalSymbolStore
    from pdb_.symbolserver import HttpSymbolServer
    from pdb_.symbolserver import SymbolServerService
    from ghidra.framework import Application

    from java.io import File
    from java.net import URI
    from java.util import ArrayList

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