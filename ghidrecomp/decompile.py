from pathlib import Path
from typing import Union, TYPE_CHECKING

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


def decompile_func(func: 'ghidra.program.model.listing.Function', decompilers: dict, thread_id: int = 0, TIMEOUT: int = 0, monitor=None) -> list:
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

    return [f'{func.getName()[:MAX_PATH_LEN]}-{func.iD}', code, sig]


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
