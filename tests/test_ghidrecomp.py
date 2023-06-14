import pytest
from pathlib import Path

from ghidrecomp import decompile, get_parser


def test_decomplie_ls(shared_datadir: Path):

    parser = get_parser()

    bin_path = shared_datadir / 'ls_aarch64'

    args = parser.parse_args([f"{bin_path.absolute()}", "--skip-cache"])

    expected_output_path = Path(args.output_path) / bin_path.name

    all_funcs, decompilations, output_path, compiler, lang_id, callgraphs = decompile(args)

    assert len(all_funcs) == 532
    assert len(decompilations) == 532
    assert output_path == expected_output_path
    assert compiler == 'unknown'
    assert lang_id == 'AARCH64:LE:64:v8A'
    assert len(callgraphs) == 0


def test_decomplie_ls_cached(shared_datadir: Path):

    parser = get_parser()

    bin_path = shared_datadir / 'ls_aarch64'

    args = parser.parse_args([f"{bin_path.absolute()}"])

    expected_output_path = Path(args.output_path) / bin_path.name

    all_funcs, decompilations, output_path, compiler, lang_id, callgraphs = decompile(args)

    assert len(all_funcs) == 532
    assert len(decompilations) == 0
    assert output_path == expected_output_path
    assert compiler == 'unknown'
    assert lang_id == 'AARCH64:LE:64:v8A'
    assert len(callgraphs) == 0


def test_ctype_filter_ls(shared_datadir: Path):

    parser = get_parser()

    bin_path = shared_datadir / 'ls_aarch64'

    args = parser.parse_args([f"{bin_path.absolute()}", "--filter", "ctype", "--skip-cache"])

    all_funcs, decompilations, output_path, compiler, lang_id, callgraphs = decompile(args)

    assert len(all_funcs) == 8
    assert len(decompilations) == 8
    assert len(callgraphs) == 0


def test_decomplie_afd(shared_datadir: Path):

    parser = get_parser()

    bin_path = shared_datadir / 'afd.sys.10.0.22621.1415'

    args = parser.parse_args([f"{bin_path.absolute()}", "--skip-cache"])

    expected_output_path = Path(args.output_path) / bin_path.name

    all_funcs, decompilations, output_path, compiler, lang_id, callgraphs = decompile(args)

    assert len(all_funcs) == 1275
    assert len(decompilations) == 1275
    assert output_path == expected_output_path
    assert compiler == 'visualstudio:unknown'
    assert lang_id == 'x86:LE:64:default'
    assert len(callgraphs) == 0


def test_decomplie_afd_cached(shared_datadir: Path):

    parser = get_parser()

    bin_path = shared_datadir / 'afd.sys.10.0.22621.1415'

    args = parser.parse_args([f"{bin_path.absolute()}"])

    expected_output_path = Path(args.output_path) / bin_path.name

    all_funcs, decompilations, output_path, compiler, lang_id, callgraphs = decompile(args)

    assert len(all_funcs) == 1275
    assert len(decompilations) == 0
    assert output_path == expected_output_path
    assert compiler == 'visualstudio:unknown'
    assert lang_id == 'x86:LE:64:default'
    assert len(callgraphs) == 0
