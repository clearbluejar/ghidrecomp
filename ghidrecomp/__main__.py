import argparse
import multiprocessing
import concurrent.futures
from pathlib import Path
from time import time
import pyhidra

from .utility import set_pdb, setup_symbol_server, set_remote_pdbs, analyze_program
from .decompile import decompile_func, decompile_to_single_file, setup_decompliers

THREAD_COUNT = multiprocessing.cpu_count()


def main():
    parser = argparse.ArgumentParser(description='ghidrecomp - A Command Line Ghidra Decompiler',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('bin', help='Path to binary used for analysis')
    parser.add_argument('--cppexport', action='store_true', help='Use Ghidras CppExporter to decompile to single file')
    parser.add_argument('--filter', help='Regex filter for function name')
    parser.add_argument('--project-path', help='Path to base ghidra projects ', default='.ghidra_projects')
    parser.add_argument('-o', '--output-path', help='Location for all decompilations', default='decompilations')

    group = parser.add_mutually_exclusive_group()
    group.add_argument('--sym-file-path', help='Specify single pdb symbol file for bin')
    group.add_argument('-s', '--symbols-path', help='Path for local symbols directory', default='.symbols')
    group.add_argument('--skip-symbols', help='Do not apply symbols', action='store_true')

    parser.add_argument('-t', '--thread-count', type=int,
                        help='Threads to use for processing. Defaults to cpu count', default=THREAD_COUNT)

    args = parser.parse_args()

    bin_path = Path(args.bin)
    project_location = Path(args.project_path)
    thread_count = args.thread_count

    output_path = Path(args.output_path) / bin_path.name
    output_path.mkdir(exist_ok=True, parents=True)

    with pyhidra.open_program(bin_path, project_location=project_location, project_name=bin_path.name, analyze=False) as flat_api:

        from ghidra.util.task import ConsoleTaskMonitor
        monitor = ConsoleTaskMonitor()

        program: "ghidra.program.model.listing.Program" = flat_api.getCurrentProgram()

        if not args.skip_symbols:
            if args.sym_file_path:
                set_pdb(program, args.sym_file_path)
            else:
                setup_symbol_server(args.symbols_path)

                set_remote_pdbs(program, True)

                # pdb = get_pdb(program)
                # assert pdb is not None

        # analyze program if we haven't yet
        analyze_program(program, verbose=True)

        all_funcs = []
        skip_count = 0

        for f in program.functionManager.getFunctions(True):

            # TODO implement filter
            # if f.getName().startswith('FUN_'):
            #     # skip FUN for demo
            #     skip_count += 1
            #     continue

            all_funcs.append(f)

        # print(f'Skipped {skip_count} FUN_ functions')

        if args.cppexport:
            print(f"Decompiling {len(all_funcs)} functions using Ghidra's CppExporter")
            c_file = Path(args.output_path) / Path(bin_path.name + '.c')
            start = time()
            decompile_to_single_file(c_file, program)
            print(f'Decompiled {len(all_funcs)} functions for {program.name} in {time() - start}')
            print(f"Wrote results to {c_file} and {c_file.stem + '.h'}")
        else:
            print(f'Decompiling {len(all_funcs)} functions using {thread_count} threads')

            decompilers = setup_decompliers(program, thread_count)

            completed = 0
            decompilations = []
            start = time()
            with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
                futures = (executor.submit(decompile_func, func, decompilers, thread_id % thread_count, monitor=monitor)
                           for thread_id, func in enumerate(all_funcs))

                for future in concurrent.futures.as_completed(futures):
                    decompilations.append(future.result())
                    completed += 1
                    if (completed % 100) == 0:
                        print(f'Completed {completed} and {int(completed/len(all_funcs)*100)}%')

            print(f'Decompiled {completed} functions for {program.name} in {time() - start}')

            start = time()
            with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
                futures = (executor.submit((output_path / (name + '.c')).write_text, decomp)
                           for name, decomp, sig in decompilations)

                for future in concurrent.futures.as_completed(futures):
                    decompilations.append(future.result())

            print(f'Wrote {completed} decompilations for {program.name} to {output_path} in {time() - start}')


if __name__ == "__main__":
    main()
