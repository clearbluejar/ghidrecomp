import pytest
import tempfile
import os
from pathlib import Path

from ghidrecomp import decompile, get_parser

# Number of functions to generate to ensure we exceed the default condense_threshold of 50
NUM_FUNCS = 200 # Using 55 to ensure enough functions for condensation

@pytest.fixture(scope="module")
def condensed_test_binary():
    """Create a test binary with many functions to trigger callgraph condensation."""
    
    # Generate a long chain of function calls
    c_code = "#include <stdio.h>\n\n"
    
    # Function declarations
    for i in range(NUM_FUNCS):
        c_code += f"void f{i}();\n"
    
    c_code += "\n"

    # Function definitions
    for i in range(NUM_FUNCS):
        c_code += f"void f{i}() {{\n"
        if i + 1 < NUM_FUNCS:
            c_code += f"    f{i+1}();\n"
        else:
            # Last function just prints
            c_code += '    printf(\"end of chain\");\n'
        c_code += "}\n\n"

    # Main function
    c_code += """
int main() {
    f0();
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

def test_condensed_called_callgraph(condensed_test_binary):
    """
    Tests that a large 'called' callgraph (e.g., from main) is condensed.
    """
    bin_file = Path(condensed_test_binary)

    parser = get_parser()
    args = parser.parse_args([
        str(bin_file.absolute()),
        "--callgraphs",
        "--cg-direction", "called",
        "--skip-cache",
        "--filter", r"\bmain\b" # We only need one callgraph to check for condensation
    ])

    all_funcs, decompilations, output_path, compiler, lang_id, callgraphs, sast_sarifs = decompile(args)

    assert len(callgraphs) > 0, "No callgraphs were generated"

    # We expect the 'called' graph for main to be generated.
    main_called_graph_data = None
    for name, direction, callgraph, graphs in callgraphs:
        if "main" in name and direction == "called":
            main_called_graph_data = graphs
            break
    
    assert main_called_graph_data is not None, "Could not find 'called' graph for main"

    flow_chart = ""
    for ctype, chart in main_called_graph_data:
        if ctype == 'flow':
            flow_chart = chart
            break

    assert "hidden links" in flow_chart, "Called callgraph for main was not condensed"
    assert "main" in flow_chart, "Called callgraph for main missing expected function main"
    assert "printf" in flow_chart, "Bottom layers missing expected function printf"

def test_condensed_calling_callgraph(condensed_test_binary):
    """
    Tests that a large 'calling' callgraph (e.g., for sink_func) is condensed.
    """
    bin_file = Path(condensed_test_binary)

    parser = get_parser()
    args = parser.parse_args([
        str(bin_file.absolute()),
        "--callgraphs",
        "--cg-direction", "calling", # Request calling graph
        "--skip-cache",
        "--filter", "printf", # Filter for sink_func
        "--top-layers", "2", # Limit to top 2 layers to keep test fast
        "--bottom-layers", "2",
        "--max-time-cg-gen", "360",
    ])

    all_funcs, decompilations, output_path, compiler, lang_id, callgraphs, sast_sarifs = decompile(args)

    assert len(callgraphs) > 0, "No callgraphs were generated"

    printf_calling_graph_data = None
    for name, direction, callgraph, graphs in callgraphs:
        if "printf" in name and direction == "calling":
            if graphs[0][1] == graphs[1][1]:
                continue # Skip strange case with externals
            printf_calling_graph_data = graphs
            break
    
    assert printf_calling_graph_data is not None, "Could not find 'calling' graph for sink_func"

    flow_chart = ""
    for ctype, chart in printf_calling_graph_data:
        if ctype == 'flow':
            flow_chart = chart
            break
            
    
    assert "hidden links" in flow_chart, "Calling callgraph for sink_func was not condensed"
    assert "main" in flow_chart, "Calling callgraph for sink_func missing expected function main"
    assert "f0" in flow_chart, "Top layers missing expected function f0"
    assert "f2" not in flow_chart, "Function f1 should be condensed out"
    assert "printf" in flow_chart, "Bottom layers missing expected function printf"
    assert "f198" not in flow_chart, "Function f199 should be condensed out"
    
def test_condensed_calling_callgraph_dynamic(condensed_test_binary):
    """
    Tests that a large 'calling' callgraph (e.g., for sink_func) is condensed.
    """
    bin_file = Path(condensed_test_binary)

    parser = get_parser()
    args = parser.parse_args([
        str(bin_file.absolute()),
        "--callgraphs",
        "--cg-direction", "calling", # Request calling graph
        "--skip-cache",
        "--filter", "printf", # Filter for sink_func
        "--max-time-cg-gen", "360",
    ])

    all_funcs, decompilations, output_path, compiler, lang_id, callgraphs, sast_sarifs = decompile(args)

    assert len(callgraphs) > 0, "No callgraphs were generated"

    printf_calling_graph_data = None
    for name, direction, callgraph, graphs in callgraphs:
        if "printf" in name and direction == "calling":
            if graphs[0][1] == graphs[1][1]:
                continue # Skip strange case with externals
            printf_calling_graph_data = graphs
            break
    
    assert printf_calling_graph_data is not None, "Could not find 'calling' graph for sink_func"

    flow_chart = ""
    for ctype, chart in printf_calling_graph_data:
        if ctype == 'flow':
            flow_chart = chart
            break
            
    assert "hidden links" in flow_chart, "Calling callgraph for sink_func was not condensed"
    assert "main" in flow_chart, "Calling callgraph for sink_func missing expected function main"
    assert "printf" in flow_chart, "Bottom layers missing expected function printf"
