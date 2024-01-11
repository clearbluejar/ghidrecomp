import argparse
import re
from pathlib import Path

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *


def add_bsim_args_to_parser(parser: argparse.ArgumentParser):
    
    group = parser.add_argument_group('BSim Options')
    group.add_argument('--bsim',  help='Generate BSim function feature vector signatures', action='store_true')
    group.add_argument('--bsim-sig-path',  help='Path to store BSim xml sigs', default='bsim-xmls')
    group.add_argument('--bsim-template',  help='BSim database template', default='medium_nosize')
    # group.add_argument('--bsim-db',  help='Path to local BSim database', default=None)
    #group.add_argument('--bsim-cat',  help='BSim category', action='append')
    #group.add_argument('--bsim-ftag',  help='BSim function', action='append')
    
    #group.add_argument('--bsim-filter',
    #                   help='Only generate sigs for functions matching regex filter', default='.')
    
# TODO
# def create_local_h2_db(db_path: Path):
#     pass

# def add_program_to_bsim_db(db_path: Path, func_filter: str):
#     pass

def gen_bsim_sigs_for_program(prog: "ghidra.program.model.listing.Program", sigs_path: Path, bsim_template, all_funcs=None):
    """
    Generates signatures for all the functions in a program
    Optionally: geneatures sigs for funcs passed into all_funcs
    """

    # see Ghidra/Features/BSim/ghidra_scripts/GenerateSignatures.py

    import java.lang.System as System
    import java.io.File as File
    import ghidra.features.bsim.query.FunctionDatabase as FunctionDatabase
    import ghidra.features.bsim.query.GenSignatures as GenSignatures
    import java.io.FileWriter as FileWriter
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.program.model.address import AddressSet

    md5String = prog.getExecutableMD5()
    monitor = ConsoleTaskMonitor().DUMMY_MONITOR
    sigs_path = Path(sigs_path)
    sigs_path.mkdir(exist_ok=True,parents=True)


    if (md5String is None) or (len(md5String) < 10):
        raise Exception("Could not get MD5 on file: " + prog.getName())
    basename = "sigs_" + md5String + "_" + prog.getName()
    System.setProperty("ghidra.output",basename)
    if not sigs_path.exists():
        raise FileNotFoundError(f'Missing dir {sigs_path}')

    # TODO pull this into a init func for gensig
    vectorFactory = FunctionDatabase.generateLSHVectorFactory()
    gensig = GenSignatures(True)
    templateName = bsim_template
    config = FunctionDatabase.loadConfigurationTemplate(templateName)
    vectorFactory.set(config.weightfactory, config.idflookup, config.info.settings)
    gensig.setVectorFactory(vectorFactory)
    gensig.addExecutableCategories(config.info.execats)
    gensig.addFunctionTags(config.info.functionTags)
    gensig.addDateColumnName(config.info.dateColumnName)
    repo = "ghidra://localhost/" + prog.getName()
    path = GenSignatures.getPathFromDomainFile(prog)
    gensig.openProgram(prog,None,None,None,repo,path)
    
    # Only generate sigs for filter
    if all_funcs is not None:
        # convert functions to Function Iterator
        # Ghidra/Features/Base/ghidra_scripts/SelectFunctionsScript.java#L30
        all_func_addr_set = AddressSet()
        fman = prog.getFunctionManager()

        for func in all_funcs:
            all_func_addr_set.add(func.getBody())
        iter = fman.getFunctions(all_func_addr_set,True)
        gensig.scanFunctions(iter, len(all_funcs), monitor)
    else:
        # generate for all functions
        iter = fman.getFunctions(True)
        gensig.scanFunctions(iter, fman.getFunctionCount(), monitor)
    
    # write out sig
    outfile = File(str(sigs_path.absolute()),basename)
    fwrite = FileWriter(outfile)
    manager = gensig.getDescriptionManager()
    manager.saveXml(fwrite)
    fwrite.close()

    return (basename, gensig, manager)
