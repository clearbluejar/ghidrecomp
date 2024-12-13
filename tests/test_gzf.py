import pytest
from pathlib import Path

import pyhidra
from ghidrecomp import decompile, get_parser
from ghidrecomp.decompile import get_bin_output_path, gen_proj_bin_name_from_path
from ghidrecomp.bsim import has_bsim, add_bsim_args_to_parser, add_categories_to_prog
from pyhidra import HeadlessPyhidraLauncher
from pathlib import Path


def test_gzf_created(shared_datadir: Path):

    parser = get_parser()

    bin_path = shared_datadir / 'ls_aarch64'

    args = parser.parse_args([f"{bin_path.absolute()}", "--filter", "ctype", "--skip-cache", "--gzf"])

    bin_proj_name = gen_proj_bin_name_from_path(bin_path)
    expected_output_path = get_bin_output_path(args.output_path, bin_proj_name)

    gzf_output_path = Path(args.output_path) / 'gzfs' / f"{bin_proj_name}.gzf"

    all_funcs, decompilations, output_path, compiler, lang_id, callgraphs = decompile(args)

    assert len(all_funcs) == 8
    assert len(decompilations) == 8
    assert len(callgraphs) == 0
    assert expected_output_path == output_path
    assert gzf_output_path.exists()


def test_gzf_created_with_path(shared_datadir: Path):

    parser = get_parser()

    bin_path = shared_datadir / 'ls_aarch64'
    gzf_custom_path = shared_datadir / "custom_gzf"

    args = parser.parse_args([f"{bin_path.absolute()}", "--filter", "ctype", "--skip-cache",
                              "--gzf", "--gzf-path", str(gzf_custom_path)])

    bin_proj_name = gen_proj_bin_name_from_path(bin_path)
    expected_output_path = get_bin_output_path(args.output_path, bin_proj_name)

    gzf_output_path = gzf_custom_path / f"{bin_proj_name}.gzf"

    all_funcs, decompilations, output_path, compiler, lang_id, callgraphs = decompile(args)

    assert len(all_funcs) == 8
    assert len(decompilations) == 8
    assert len(callgraphs) == 0
    assert expected_output_path == output_path
    assert gzf_custom_path.exists()
