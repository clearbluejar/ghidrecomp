import argparse
import multiprocessing

from ghidrecomp import __version__

from .callgraph import add_cg_args_to_parser
from .bsim import add_bsim_args_to_parser

THREAD_COUNT = multiprocessing.cpu_count()

def get_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(description='ghidrecomp - A Command Line Ghidra Decompiler',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('bin', help='Path to binary used for analysis')
    parser.add_argument('--cppexport', action='store_true', help='Use Ghidras CppExporter to decompile to single file')
    parser.add_argument('--filter', dest='filters', action='append', help='Regex match for function name')
    parser.add_argument('--project-path', help='Path to base ghidra projects ', default='ghidra_projects')
    parser.add_argument('--gdt', help='Additional GDT to apply', nargs='?', action='append')
    parser.add_argument('-o', '--output-path', help='Location for all decompilations', default='ghidrecomps')
    parser.add_argument("-v", "--version", action="version", version=__version__)
    parser.add_argument("--skip-cache", action='store_true',
                        help='Skip cached and genearate new decomp and callgraphs.')

    group = parser.add_mutually_exclusive_group()
    group.add_argument('--sym-file-path', help='Specify single pdb symbol file for bin')
    group.add_argument('-s', '--symbols-path', help='Path for local symbols directory', default='symbols')
    group.add_argument('--skip-symbols', help='Do not apply symbols', action='store_true')

    parser.add_argument('-t', '--thread-count', type=int,
                        help='Threads to use for processing. Defaults to cpu count', default=THREAD_COUNT)
    parser.add_argument('--va', help='Enable verbose analysis', action='store_true')
    parser.add_argument('--fa', help='Force new analysis (even if already analyzed)', action='store_true')

    group = parser.add_argument_group('JVM Options')
    group.add_argument('--max-ram-percent', help='Set JVM Max Ram %% of host RAM', default=50.0)
    group.add_argument('--print-flags', help='Print JVM flags at start', action='store_true')

    add_cg_args_to_parser(parser)

    add_bsim_args_to_parser(parser)
    

    return parser