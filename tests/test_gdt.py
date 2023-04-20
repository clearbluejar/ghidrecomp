import contextlib
from pathlib import Path
from typing import Union, TYPE_CHECKING, Tuple, ContextManager, List

import pyhidra
from pyhidra.core import _setup_project, _analyze_program
from ghidrecomp.utility import apply_gdt, get_parser, setup_symbol_server, set_remote_pdbs
from ghidrecomp.decompile import analyze_program

if TYPE_CHECKING:
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.listing import Program

# this function is need to open a program and not save it on exit.


@contextlib.contextmanager
def open_program_dont_save(
        binary_path: Union[str, Path],
        project_location: Union[str, Path] = None,
        project_name: str = None,
        analyze=True,
        language: str = None,
        compiler: str = None,
) -> ContextManager["FlatProgramAPI"]:
    """
    Opens given binary path in Ghidra and returns FlatProgramAPI object.

    :param binary_path: Path to binary file, may be None.
    :param project_location: Location of Ghidra project to open/create.
        (Defaults to same directory as binary file)
    :param project_name: Name of Ghidra project to open/create.
        (Defaults to name of binary file suffixed with "_ghidra")
    :param analyze: Whether to run analysis before returning.
    :param language: The LanguageID to use for the program.
        (Defaults to Ghidra's detected LanguageID)
    :param compiler: The CompilerSpecID to use for the program. Requires a provided language.
        (Defaults to the Language's default compiler)
    :return: A Ghidra FlatProgramAPI object.
    :raises ValueError: If the provided language or compiler is invalid.
    """

    from pyhidra.launcher import PyhidraLauncher, HeadlessPyhidraLauncher

    if not PyhidraLauncher.has_launched():
        HeadlessPyhidraLauncher().start()

    from ghidra.app.script import GhidraScriptUtil
    from ghidra.program.flatapi import FlatProgramAPI

    project, program = _setup_project(
        binary_path,
        project_location,
        project_name,
        language,
        compiler
    )
    GhidraScriptUtil.acquireBundleHostReference()

    try:
        flat_api = FlatProgramAPI(program)

        if analyze:
            _analyze_program(flat_api, program)

        yield flat_api
    finally:
        GhidraScriptUtil.releaseBundleHostReference()

        # project.save(program)
        project.close()


def test_apply_gdt(shared_datadir: Path):

    parser = get_parser()

    bin_path = shared_datadir / 'afd.sys.10.0.22621.1415'
    gdt_path = shared_datadir / 'ntddk_64.gdt'

    parser = get_parser()

    args = parser.parse_args([f"{bin_path.absolute()}"])

    project_location = Path(args.project_path)
    output_path = Path(args.output_path) / bin_path.name
    output_path.mkdir(exist_ok=True, parents=True)

    # turn on verbose
    pyhidra.start(True)

    symbol_to_test = 'IoAcquireCancelSpinLock'
    expected_gdt_signature = 'void IoAcquireCancelSpinLock(PKIRQL Irql)'

    # open for analysis save it
    with pyhidra.open_program(bin_path, project_location=project_location, project_name=bin_path.name, analyze=False) as flat_api:
        from ghidra.program.model.listing import Program

        program: "Program" = flat_api.getCurrentProgram()

        setup_symbol_server(args.symbols_path)

        set_remote_pdbs(program, True)

        # analyze program if we haven't yet
        analyze_program(program, verbose=args.va)

    # open to test gdt, don't save
    with open_program_dont_save(bin_path, project_location=project_location, project_name=bin_path.name, analyze=False) as flat_api:

        from ghidra.program.model.listing import Program

        program: "Program" = flat_api.getCurrentProgram()

        signature_before_gdt = None

        for f in program.functionManager.externalFunctions:

            if f'{f.getName()}' == symbol_to_test:
                print(f)
                signature_before_gdt = f'{f.getSignature()}'

        assert signature_before_gdt is not None
        assert signature_before_gdt is not expected_gdt_signature

        apply_gdt(program, gdt_path)

        signature_after_gdt = None
        for f in program.functionManager.externalFunctions:

            if f'{f.getName()}' == symbol_to_test:
                print(f)
                signature_after_gdt = f'{f.getSignature()}'

        print(signature_before_gdt)
        print(signature_after_gdt)
        print(expected_gdt_signature)
        assert signature_before_gdt != signature_after_gdt
        assert expected_gdt_signature == signature_after_gdt
