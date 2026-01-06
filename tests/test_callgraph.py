import pytest
import tempfile
import os
from pathlib import Path

from ghidrecomp import decompile, get_parser
from ghidrecomp.decompile import get_bin_output_path, gen_proj_bin_name_from_path

@pytest.fixture(scope="module")
def test_binary():
    """Create a simple test binary for testing."""
    c_code = """
#include <stdio.h>
void child() {
    printf("child");
}

int main() {
    child();
    return 0;
}
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        f.write(c_code)
        c_file = f.name

    bin_file = c_file.replace(".c", "")

    # Check if gcc is available
    if os.system("which gcc > /dev/null 2>&1") != 0:
        pytest.skip("gcc not found, skipping test that requires compilation")

    os.system(f"gcc -o {bin_file} {c_file}")

    yield bin_file

    os.unlink(c_file)
    os.unlink(bin_file)

def test_decomplie_afd_callgraphs(shared_datadir: Path):

    parser = get_parser()

    bin_path = shared_datadir / 'afd.sys.10.0.22621.1415'

    args = parser.parse_args([f"{bin_path.absolute()}", "--callgraph-filter", "AfdRe",
                             "--filter", "AfdRe", "--callgraphs", "--skip-cache"])

    bin_proj_name = gen_proj_bin_name_from_path(bin_path)
    expected_output_path = get_bin_output_path(args.output_path, bin_proj_name)

    all_funcs, decompilations, output_path, compiler, lang_id, callgraphs, sast_sarifs = decompile(args)

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

    bin_proj_name = gen_proj_bin_name_from_path(bin_path)
    expected_output_path = get_bin_output_path(args.output_path, bin_proj_name)

    all_funcs, decompilations, output_path, compiler, lang_id, callgraphs, sast_sarifs = decompile(args)

    assert len(all_funcs) == 73
    assert len(decompilations) == 0
    assert output_path == expected_output_path
    assert compiler == 'visualstudio:unknown'
    assert lang_id == 'x86:LE:64:default'
    assert len(callgraphs) == 0

def test_decomplie_afd_callgraphs_called_and_calling(shared_datadir: Path):

    parser = get_parser()

    bin_path = shared_datadir / 'afd.sys.10.0.22621.1415'

    args = parser.parse_args([f"{bin_path.absolute()}", "--callgraph-filter", "AfdRe",
                             "--filter", "AfdRe", "--callgraphs", "--skip-cache", "--cg-direction", "both"])

    bin_proj_name = gen_proj_bin_name_from_path(bin_path)
    expected_output_path = get_bin_output_path(args.output_path, bin_proj_name)

    all_funcs, decompilations, output_path, compiler, lang_id, callgraphs, sast_sarifs = decompile(args)

    assert len(all_funcs) == 73
    assert len(decompilations) == 73
    assert output_path == expected_output_path
    assert compiler == 'visualstudio:unknown'
    assert lang_id == 'x86:LE:64:default'
    assert len(callgraphs) == 146

def test_callgraph_bin(test_binary):
    """
    Tests callgraph generation on a dynamically compiled binary.
    """
    bin_file = Path(test_binary)

    parser = get_parser()
    args = parser.parse_args([
        str(bin_file.absolute()),
        "--callgraphs",
        "--skip-cache",
        "--cg-direction", "both",
        # Use word boundaries to avoid matching __libc_start_main
        "--filter", r"\bmain\b|\bchild\b"
    ])

    all_funcs, decompilations, output_path, compiler, lang_id, callgraphs, sast_sarifs = decompile(args)

    # Filter for the functions we are interested in
    main_funcs = [f for f in all_funcs if f.name == "main"]
    child_funcs = [f for f in all_funcs if f.name == "child"]

    assert len(main_funcs) >= 1, "Could not find main function"
    assert len(child_funcs) >= 1, "Could not find child function"

    # we should have a calling and called graph for each of the filtered functions
    assert len(callgraphs) >= 4 # at least 2 funcs * 2 directions

    main_called_graph = None
    child_calling_graph = None

    for name, direction, callgraph, graphs in callgraphs:
        if "main" in name and direction == "called":
            main_called_graph = callgraph
        if "child" in name and direction == "calling":
            child_calling_graph = callgraph

    assert main_called_graph is not None, "Could not find 'called' graph for main"
    assert child_calling_graph is not None, "Could not find 'calling' graph for child"

    # In main's "called" graph, 'child' should be reachable.
    # The cg root is main. The graph shows main -> child.
    assert main_called_graph.is_reachable("main", "child")

    # In child's "calling" graph, 'main' should be a caller.
    # The cg root is child. The graph shows main -> child.
    assert child_calling_graph.is_reachable("main", "child")

    # Let's check the reverse which should not be true.
    # In main's "called" graph, main is not reachable from child.
    assert not main_called_graph.is_reachable("child", "main")