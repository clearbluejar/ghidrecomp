from pathlib import Path

from ghidrecomp import decompile, get_parser


def test_decomplie_afd_callgraphs(shared_datadir: Path):

    parser = get_parser()

    bin_path = shared_datadir / 'afd.sys.10.0.22621.1415'

    args = parser.parse_args([f"{bin_path.absolute()}", "--callgraph-filter", "AfdRe",
                             "--filter", "AfdRe", "--callgraphs", "--skip-cache"])

    expected_output_path = Path(args.output_path) / bin_path.name

    all_funcs, decompilations, output_path, compiler, lang_id, callgraphs = decompile(args)

    assert len(all_funcs) == 73
    assert len(decompilations) == 73
    assert output_path == expected_output_path
    assert compiler == 'visualstudio:unknown'
    assert lang_id == 'x86:LE:64:default'
    assert len(callgraphs) == 73


def test_decomplie_afd_callgraphs_cached(shared_datadir: Path):

    parser = get_parser()

    bin_path = shared_datadir / 'afd.sys.10.0.22621.1415'

    args = parser.parse_args([f"{bin_path.absolute()}", "--callgraph-filter", "AfdRe",
                             "--filter", "AfdRe", "--callgraphs"])

    expected_output_path = Path(args.output_path) / bin_path.name

    all_funcs, decompilations, output_path, compiler, lang_id, callgraphs = decompile(args)

    assert len(all_funcs) == 73
    assert len(decompilations) == 0
    assert output_path == expected_output_path
    assert compiler == 'visualstudio:unknown'
    assert lang_id == 'x86:LE:64:default'
    assert len(callgraphs) == 0
