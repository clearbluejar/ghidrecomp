import argparse
import re
from pathlib import Path

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *

def has_bsim() -> bool:

    from ghidra.feature.vt import api as vtapi
    has_bsim = False

    has_bsim = hasattr(vtapi,'BSimProgramCorrelatorFactory')
    
    return has_bsim

def add_bsim_args_to_parser(parser: argparse.ArgumentParser):
    
    group = parser.add_argument_group('BSim Options')
    group.add_argument('--bsim',  help='Generate BSim function feature vector signatures', action='store_true')
    group.add_argument('--bsim-sig-path',  help='Path to store BSim xml sigs', default='bsim-xmls')
    group.add_argument('--bsim-template',  help='BSim database template', default='medium_nosize')
    # group.add_argument('--bsim-db',  help='Path to local BSim database', default=None)
    group.add_argument('--bsim-cat',  help='BSim category. (type:value) --bsim-cat color:red', action='append')
    #group.add_argument('--bsim-ftag',  help='BSim function', action='append')
    
# TODO
# def create_local_h2_db(db_path: Path):
#     pass

# TODO
# def add_program_to_bsim_db(db_path: Path, func_filter: str):
#     pass
    

def add_categories_to_prog(prog,categories) -> list:
    """
    Need to set program option first
    See: Features/BSim/src/main/java/ghidra/features/bsim/query/GenSignatures.java#L231
    """

    from ghidra.program.model.listing import Program

    prog_opts = prog.getOptions(Program.PROGRAM_INFO)
    cat_types = []

    # #debug
    # for name in prog_opts.optionNames:
    #     print(f'{name} : {prog_opts.getDefaultValueAsString(name)}')

    for cat in categories:
        if cat.find(':') == -1:
            # no cat option value defined (assume default prog option)
            cat_type = cat
            val = prog_opts.getDefaultValueAsString(cat_type)
            if not prog_opts.contains(cat_type):
                raise ValueError(f'--bsim-cat arg "{cat_type}" provided is not valid. Custom types need value suppled type:value.')
        else:
            cat_type,val = cat.split(':')
            prog_opts.setString(cat_type, val)

        cat_types.append(cat_type)

        print(f'Adding category type:{cat_type} val:{val}')

    return cat_types


def remove_temp_prog_options(prog,categories):
    """
    remove non permanent options (cats already added)
    this is to avoid cluttering up program options
    """

    from ghidra.program.model.listing import Program

    prog_opts = prog.getOptions(Program.PROGRAM_INFO)

    for cat in categories:
        if cat.find(':') != -1:
            cat_type,val = cat.split(':')
            prog_opts.removeOption(cat_type)
            assert not prog_opts.contains(cat_type)
        else:
            assert prog_opts.contains(cat)

def gen_bsim_sigs_for_program(prog: "ghidra.program.model.listing.Program", sigs_path: Path, bsim_template,categories=None,all_funcs=None):
    """
    Generates signatures for all the functions in a program
    Optionally: geneatures sigs for funcs passed into all_funcs
    """

    if not has_bsim():
        raise Exception('Calling BSim but BSim is not found')

    # see Ghidra/Features/BSim/ghidra_scripts/GenerateSignatures.py

    import java.lang.System as System
    import java.io.File as File
    from java.util import ArrayList
    import ghidra.features.bsim.query.FunctionDatabase as FunctionDatabase
    import ghidra.features.bsim.query.GenSignatures as GenSignatures
    from ghidra.features.bsim.query.description import DescriptionManager

    import java.io.FileWriter as FileWriter
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.program.model.address import AddressSet
    from ghidra.framework.protocol.ghidra import GhidraURL

    md5String = prog.getExecutableMD5()
    monitor = ConsoleTaskMonitor().DUMMY_MONITOR
    sigs_path = Path(sigs_path)
    sigs_path.mkdir(exist_ok=True,parents=True)
    cat_add_count = 0
    func_count = 0


    if (md5String is None) or (len(md5String) < 10):
        raise Exception("Could not get MD5 on file: " + prog.getName())
    basename = "sigs_" + md5String + "_" + prog.getName()
    System.setProperty("ghidra.output",basename)
    if not sigs_path.exists():
        raise FileNotFoundError(f'Missing dir {sigs_path}')
    # TODO pull this into a init func for gensig
    vectorFactory = FunctionDatabase.generateLSHVectorFactory()
    gensig : GenSignatures = GenSignatures(True)
    templateName = bsim_template
    config = FunctionDatabase.loadConfigurationTemplate(templateName)
    vectorFactory.set(config.weightfactory, config.idflookup, config.info.settings)
    gensig.setVectorFactory(vectorFactory)
    # this adds from db config
    gensig.addExecutableCategories(config.info.execats)
    gensig.addFunctionTags(config.info.functionTags)
    gensig.addDateColumnName(config.info.dateColumnName)
    
    df = prog.getDomainFile().getParent()
    folderURL = df.getLocalProjectURL()
    normalizedProjectURL = GhidraURL.getProjectURL(folderURL);
    repo = normalizedProjectURL.toExternalForm();
    path = GenSignatures.getPathFromDomainFile(prog)

    # add custom exe categories
    if categories is not None:
        cat_types = add_categories_to_prog(prog, categories)
        cats = ArrayList()
        
        # add cat to list
        for cat_type in cat_types:
            cats.add(cat_type)

        # add arg categories to gensig
        gensig.addExecutableCategories(cats)

    gensig.openProgram(prog,None,None,None,repo,path)

    if categories is not None:
        remove_temp_prog_options(prog,categories)
    
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
    manager : DescriptionManager  = gensig.getDescriptionManager()
    func_count = manager.numFunctions()
    # if er.nameExec == prog.getName()
    if categories is not None:
        manager_cats = [(cat.type,cat.category) for er in manager.executableRecordSet if er.allCategories is not None for cat in er.allCategories  ]
        print(f'Categories added: {manager_cats}')
        cat_add_count = len(manager_cats)
        assert cat_add_count == len(categories)
    manager.saveXml(fwrite)
    fwrite.close()

    # close
    gensig.dispose();

    return (basename,func_count, cat_add_count)
