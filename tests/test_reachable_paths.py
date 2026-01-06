import pytest
import tempfile
import os
from pathlib import Path

from ghidrecomp import decompile, get_parser

@pytest.fixture(scope="module")
def multipath_test_binary():
    """Create a test binary with multiple paths between functions."""
    c_code = """
#include <stdio.h>

// Forward declarations
void a();
void b();
void c();
void d();
void e();

void d() { printf("d"); }
void e() { printf("e"); }
void c() { d(); e(); }
void a() { c(); }
void b() { d(); }

int main() {
    a();
    b();
    return 0;
}
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        f.write(c_code)
        c_file = f.name

    bin_file = c_file.replace(".c", "")

    if os.system("which gcc > /dev/null 2>&1") != 0:
        pytest.skip("gcc not found, skipping test that requires compilation")

    os.system(f"gcc -o {bin_file} {c_file}")

    yield bin_file

    os.unlink(c_file)
    os.unlink(bin_file)

def test_get_all_paths_graph(multipath_test_binary):
    """
    Tests the get_all_paths_graph method to ensure it correctly extracts subgraphs.
    """
    bin_file = Path(multipath_test_binary)

    parser = get_parser()
    args = parser.parse_args([
        str(bin_file.absolute()),
        "--callgraphs",
        "--skip-cache",
        "--cg-direction", "called",
        "--filter", r"\bmain\b"
    ])

    _, _, _, _, _, callgraphs, sast_sarifs = decompile(args)

    main_called_graph = None
    for name, direction, callgraph, _ in callgraphs:
        if "main" in name and direction == "called":
            main_called_graph = callgraph
            break
    
    assert main_called_graph is not None, "Could not find 'called' graph for main"

    # Get the subgraph containing all paths from main to d
    paths_graph = main_called_graph.get_all_paths_graph("main", "d")

    # The subgraph should contain only the nodes in the paths
    expected_nodes = {"main", "a", "b", "c", "d"}
    path_graph_nodes = set(paths_graph.graph.keys())
    for _, edge_list in paths_graph.graph.items():
        for dst, _, _, _ in edge_list:
            path_graph_nodes.add(dst)
            
    assert path_graph_nodes == expected_nodes

    # The subgraph should not contain node 'e' which is not on any path to 'd'
    assert "e" not in path_graph_nodes

    # Check that the edges are correct
    expected_edges = {("main", "a"), ("main", "b"), ("a", "c"), ("c", "d"), ("b", "d")}
    
    actual_edges = set()
    for src, edge_list in paths_graph.graph.items():
        for dst, _, _, _ in edge_list:
            actual_edges.add((src, dst))

    assert actual_edges == expected_edges

    # Check that the edge (c, e) is not in the path graph
    assert ("c", "e") not in actual_edges