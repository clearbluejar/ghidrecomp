import pytest
from pathlib import Path

import pyhidra
from ghidrecomp import decompile, get_parser
from ghidrecomp.decompile import get_bin_output_path, gen_proj_bin_name_from_path
from ghidrecomp.bsim import has_bsim,add_bsim_args_to_parser,add_categories_to_prog
from pyhidra.version import get_ghidra_version

# check BSIM exists
def test_bsim_should_exist():

    pyhidra.start()

    # check ghidra version and bail if old
    if get_ghidra_version() < '11.0':
        assert not has_bsim()
    else:
        assert has_bsim()


def test_bsim_bad_known_arg(shared_datadir: Path):

    parser = get_parser()

    bin_path = shared_datadir / 'ls_aarch64'

    args = parser.parse_args([f"{bin_path.absolute()}", 
                              "--bsim-cat",
                              "CustomArgNeedsValue",
                              "--bsim"
                              ])

    if has_bsim():
        # will only parse args is has_bsim
        with pytest.raises(ValueError):

            all_funcs, decompilations, output_path, compiler, lang_id, callgraphs = decompile(args)


        x = 1 / 1

# check category + func count

def test_bsim_args_with_ls(shared_datadir: Path):

    parser = get_parser()

    bin_path = shared_datadir / 'ls_aarch64'

    args = parser.parse_args([f"{bin_path.absolute()}",
                              "--skip-cache", 
                              "--bsim-cat",
                              "Executable Location",
                              "--bsim-cat",
                              "source:ghidrecomp",
                              "--bsim"
                              ])

    bin_proj_name = gen_proj_bin_name_from_path(bin_path)
    expected_output_path = get_bin_output_path(args.output_path, bin_proj_name)

    all_funcs, decompilations, output_path, compiler, lang_id, callgraphs = decompile(args)

    assert len(all_funcs) == 532
    assert len(decompilations) == 532
    assert output_path == expected_output_path
    assert compiler == 'unknown'
    assert lang_id == 'AARCH64:LE:64:v8A'
    assert len(callgraphs) == 0

