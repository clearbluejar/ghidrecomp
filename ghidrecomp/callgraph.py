import argparse
from pathlib import Path
import re
import base64
import zlib
import json
from typing import List, Union, Tuple, TYPE_CHECKING

import pyhidra


# needed for ghidra python vscode autocomplete
if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *



class CallGraph:

    # Java imports
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.program.model.listing import Function

    def __init__(self, root=None):
        self.graph = {}
        self.title = None
        self.count = 0
        self.max_depth = 0
        self.root = root

    def set_root(self, root: str):
        self.graph.setdefault(root,[])
        self.root = root

    def add_edge(self, node1, node2, depth):

        assert self.root is not None, 'root node must be set prior to adding an edge'

        self.graph.setdefault(node1, [])
        self.graph.setdefault(node2, [])

        self.graph[node1].append((node2, depth, self.count))
        self.count += 1

        # update max depth
        if depth > self.max_depth:
            self.max_depth = depth

    def print_graph(self):
        for src, dst in self.graph.items():
            print(f"{src}-->{dst}")

    def root_at_end(self) -> bool:
        """
        Determines the direction of the graph
        """
        # if the root has no links, the root is at the end
        return len(self.graph[self.root]) == 0

    def get_endpoints(self) -> list:

        end_nodes = set()

        if not self.root_at_end():
            for src, dst in self.graph.items():
                # special case of loop
                if len(dst) == 0 or len(dst) == 1 and dst[0] == src:
                    end_nodes.add(src)
        else:
            destinations = []

            for src, dst in self.graph.items():

                # special case of loop
                if len(dst) == 1 and dst[0] == src:
                    # don't append to destinations in this case
                    continue

                for d in dst:
                    destinations.append(d[0])

            end_nodes = set(self.graph.keys()).difference(set(destinations))

        return list(end_nodes)

    def get_count_at_depth(self, depth: int) -> int:
        """
        Returns count for nodes at a specific depth
        """

        count = 0
        for src, dst in self.graph.items():

            for d in dst:
                if d[1] == depth:
                    count += 1

        return count

    def links_count(self) -> int:
        """
        Returns count of edges
        """

        count = 0
        for src, dst in self.graph.items():

            for d in dst:
                count += 1

        return count

    def gen_mermaid_flow_graph(self, direction=None, shaded_nodes: list = None, shade_color='#339933', max_display_depth=None, endpoint_only=False) -> str:
        """
        Generate MermaidJS flowchart from self.graph
        See https://mermaid.js.org/syntax/flowchart.html
        """

        # TODO mark root node with circle
        # TODO mark end_points with shape

        # used to create a key index for flowchart ids
        # once defineed, a func name can be represented by a symbol, saving space
        node_keys = {}        
        node_count = 0        
        existing_base_links = set()

        # guess best orientation
        if not direction:
            if len(self.graph) < 350:
                direction = 'TD'
            else:
                direction = 'LR'
            

        mermaid_flow = '''flowchart {direction}\n{style}\n{links}\n'''

        if shaded_nodes:
            style = f'''classDef shaded fill:{shade_color}'''
        else:
            style = ''

        if len(self.graph) == 1:
            links = [self.root]
        else:
            links = set()

            if endpoint_only:            

                endpoints = self.get_endpoints()

                for i, end in enumerate(endpoints):

                    if shaded_nodes and end in shaded_nodes:
                        end_style_class = ':::shaded'
                    else:
                        end_style_class = ''

                    if shaded_nodes and self.root in shaded_nodes:
                        root_style_class = ':::shaded'
                    else:
                        root_style_class = ''

                    if self.root_at_end():
                        link = f'{i}["{end}"]{end_style_class} --> root["{self.root}"]{root_style_class}'
                    else:
                        link = f'root["{self.root}"]{root_style_class} --> {i}["{end}"]{end_style_class}'

                    links.add(link)

            else:
                    
                for src, dst in self.graph.items():

                    if shaded_nodes and src in shaded_nodes:
                        src_style_class = ':::shaded'
                    else:
                        src_style_class = ''

                    for node in dst:

                        depth = node[1]
                        fname = node[0]

                        if max_display_depth and depth > max_display_depth:
                            continue

                        if shaded_nodes and fname in shaded_nodes:
                            dst_style_class = ':::shaded'
                        else:
                            dst_style_class = ''

                        # Build src --> dst link
                        ## Don't add duplicate links
                        ## Use short ids for func name to save space with node_keys
                        if node_keys.get(src) is None:
                            node_keys[src] = node_count
                            node_count += 1
                            src_node = f'{node_keys[src]}["{src}"]{src_style_class}'
                        else:
                            src_node = f'{node_keys[src]}{src_style_class}'

                        if node_keys.get(fname) is None:
                            node_keys[fname] = node_count
                            node_count += 1
                            dst_node = f'{node_keys[fname]}["{fname}"]{dst_style_class}'
                        else:
                            dst_node = f'{node_keys[fname]}{dst_style_class}'

                        # record base link
                        current_base_link = f'{src} --> {node[0]}'
                        
                        # don't add link if another already exists
                        if not current_base_link in existing_base_links:
                            link = f'{src_node} --> {dst_node}'
                            links.add(link)
                            existing_base_links.add(current_base_link)
                        # else:
                        #     print('Duplicate base link found!')
                
                

        return mermaid_flow.format(links='\n'.join(set(links)), direction=direction, style=style)

    def gen_mermaid_mind_map(self, max_display_depth=None) -> str:
        """
        Generate MermaidJS mindmap from self.graph
        See https://mermaid.js.org/syntax/mindmap.html
        """

        rows = []

        mermaid_mind = '''mindmap\nroot(({root}))\n{rows}\n'''

        destinations = []

        for src, dst in self.graph.items():
            for d in dst:
                destinations.append(d)

        last_depth = 0
        current_level_names = []
        for i, row in enumerate(sorted(destinations, key=lambda x: x[2])):
            depth = row[1]

            # skip root row
            if depth < 2 or max_display_depth and depth > max_display_depth:
                continue

            if depth < last_depth:
                # reset level names
                current_level_names = []

            if not row[0] in current_level_names:
                spaces = (depth+1)*'  '
                rows.append(f"{spaces}{row[0]}")
                last_depth = depth
                current_level_names.append(row[0])

        return mermaid_mind.format(rows='\n'.join(rows), root=self.root)


# don't really limit the graph
MAX_DEPTH = 10000



# Recursively calling to build calling graph
def get_calling(f: Function, cgraph: CallGraph = CallGraph(), depth: int = 0, visited: list = [], verbose=False,include_ns=True):
    """
    Build a call graph of all calling functions
    Traverses depth first
    """
    monitor = ConsoleTaskMonitor()

    if f == None:
        return None

    if depth == 0:
        if verbose:
            print(f"root({f.getName(include_ns)})")
        cgraph.set_root(f.getName(include_ns))

    if depth > MAX_DEPTH:
        return cgraph

    space = (depth+2)*'  '

    # loop check
    if [f.entryPoint.toString(), f.getName(True)] in visited:

        # calling loop
        if verbose:
            print(f"{space} - LOOOOP {f.getName(include_ns)}")

        # add ref to self
        cgraph.add_edge(f.getName(include_ns), f.getName(include_ns), depth)

        return cgraph

    calling = f.getCallingFunctions(monitor)

    visited.append([f.entryPoint.toString(), f.getName(True)])

    if len(calling) > 0:
        
        depth = depth+1

        for c in calling:

            currently_visited = visited.copy()

            if verbose:
                print(f"{space} - {c.getName(include_ns)}")

            # Add calling edge
            cgraph.add_edge(c.getName(include_ns), f.getName(include_ns), depth)

            # Parse further functions
            cgraph = get_calling(c, cgraph, depth, visited=currently_visited)

    return cgraph


# Recursively calling to build called graph
def get_called(f: Function, cgraph: CallGraph = CallGraph(), depth: int = 0, visited: list = [], verbose=False):
    """
    Build a call graph of all called functions
    Traverses depth first
    """

    if f == None:
        return None

    if depth == 0:
        if verbose:
            print(f"root({f.getName(True)})")
        cgraph.set_root(f.getName(True))

    if depth > MAX_DEPTH:
        return cgraph

    space = (depth+2)*'  '

    # loop check
    if [f.entryPoint.toString(), f.getName(True)] in visited:

        # calling loop
        if verbose:
            print(f"{space} - LOOOOP {f.getName(True)}")

        # add ref to self
        cgraph.add_edge(f.getName(), f.getName(), depth)

        return cgraph

    called = f.getCalledFunctions(monitor)

    visited.append([f.entryPoint.toString(), f.getName(True)])

    if len(called) > 0:

        depth = depth+1

        for c in called:

            currently_visited = visited.copy()

            if verbose:
                print(f"{space} - {c.getName()}")

            # Add called edge
            if c.isExternal():
                cgraph.add_edge(f.getName(), f"{c.getExternalLocation().getLibraryName()}::{c.getName()}", depth)
            else:
                cgraph.add_edge(f.getName(), c.getName(), depth)

            # Parse further functions
            cgraph = get_called(c, cgraph, depth, visited=currently_visited)

    return cgraph


def _wrap_mermaid(text: str) -> str:
    return f'''```mermaid\n{text}\n```'''

# based on serialize func  https://github.com/mermaid-js/mermaid-live-editor/blob/b5978e6faf7635e39452855fb4d062d1452ab71b/src/lib/util/serde.ts#L19-L24
def gen_mermaid_url(graph: str, edit=False) -> str:
    """
    Generate valid mermaid live edit and image links
    """
    
    mm_json = { 'code': graph, 'mermaid': { 'theme': 'dark'}, 'updateEditor': True, 'autoSync': True, 'updateDiagram': True, "editorMode":"code","panZoom": True }
    base64_string = base64.urlsafe_b64encode(zlib.compress(json.dumps(mm_json).encode('utf-8'), 9)).decode('ascii')
   
    if edit:        
        url = f'https://mermaid.live/edit#pako:{base64_string}'        
    else:
        url = f'https://mermaid.ink/img/svg/pako:{base64_string}'

    return url

def gen_callgraph_md(f: Function, called: str, calling: str, calling_entrypoints: str, called_endpoints: str, called_mind: str,calling_mind: str ):

    fname = f.getName(True)

    calling_mind_url = f'[Edit calling Mindmap]({gen_mermaid_url(calling_mind,edit=True)})'
    called_mind_url = f'![Edit called Mindmap]({gen_mermaid_url(called_mind,edit=True)})'

    md_template = f'''
# {fname}

## Calling

Functions that call `{fname}`.

### Flowchart 

[Edit on mermaid live]({gen_mermaid_url(calling,edit=True)})

{_wrap_mermaid(calling)}

### Entrypoints

A condensed view, showing only entrypoints to the callgraph.

{_wrap_mermaid(calling_entrypoints)}

### Mindmap

{calling_mind_url}

## Called

Functions that `{fname}` calls

### Flowchart

[Edit on mermaid live]({gen_mermaid_url(called,edit=True)})

{_wrap_mermaid(called)}

### Endpoints

A condensed view, showing only endpoints of the callgraph.

{_wrap_mermaid(called_endpoints)}

### Mindmap

{called_mind_url}

'''

    return md_template


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='A demo Ghidra callgraph generation script')

    parser.add_argument('bin', help='Path to binary used for analysis')
    parser.add_argument('--include',  action='append',help='Func name or partial name to include')
    parser.add_argument('-s', '--symbol-path', help='Path to symbol path for bin')
    parser.add_argument('-o', '--output-path', help='Callgraph output directory.', default='.callgraphs')
    parser.add_argument('-m', '--max-display-depth', help='Max Depth for graph generation. Will affect size of markdown')

    args = parser.parse_args()

    print(args)

    bin_path = Path(args.bin)
    cgraph_name = bin_path.name
    project_location = Path('.ghidra_projects')

    if args.max_display_depth:
        max_display_depth = int(args.max_display_depth)
    else:
        max_display_depth = None

    output_path = Path(args.output_path) / bin_path.name
    output_path.mkdir(exist_ok=True, parents=True)

    with pyhidra.open_program(bin_path, project_location=project_location, project_name=bin_path.name, analyze=False) as flat_api:

        from ghidra.program.util import GhidraProgramUtilities
        from ghidra.app.script import GhidraScriptUtil        

        program: "ghidra.program.model.listing.Program" = flat_api.getCurrentProgram()        

        # configure symbol path for bin
        if args.symbol_path:
            symbol_path = Path(args.symbol_path)
            from ghidra.app.plugin.core.analysis import PdbUniversalAnalyzer
            from java.io import File

            pdbFile = File(symbol_path)
            PdbUniversalAnalyzer.setPdbFileOption(program, pdbFile)

        # analyze program if we haven't yet
        if GhidraProgramUtilities.shouldAskToAnalyze(program):
            GhidraScriptUtil.acquireBundleHostReference()
            flat_api.analyzeAll(program)
            GhidraProgramUtilities.setAnalyzedFlag(program, True)
            GhidraScriptUtil.releaseBundleHostReference()

        all_funcs = program.functionManager.getFunctions(True)

        for f in all_funcs:

            if f.getName().startswith('FUN_'):
                # skip FUN for demo
                continue

            if args.include:
                if not any([f.getName(True).find(match) >= 0 for match in args.include]):
                    # skip functions that don't match any of the include args
                    continue

            print(f"Processing function: {f.getName(True)}")

            calling = get_calling(f)            

            if len(calling.graph) >= 700:
                # too big for demo
                print(f"Skipping {f.getName(True)}:\t\t\t\tcalling: {len(calling.graph)} {calling.max_depth}")                
                continue
            
            called = get_called(f)

            called_flow = called.gen_mermaid_flow_graph(shaded_nodes=called.get_endpoints(), max_display_depth=max_display_depth, direction='LR')
            called_flow_ends = called.gen_mermaid_flow_graph(shaded_nodes=called.get_endpoints(), endpoint_only=True, direction='LR')
            called_mind = called.gen_mermaid_mind_map(max_display_depth=3)

            calling_flow = calling.gen_mermaid_flow_graph(shaded_nodes=calling.get_endpoints(), max_display_depth=max_display_depth)
            calling_flow_ends = calling.gen_mermaid_flow_graph(shaded_nodes=calling.get_endpoints(),endpoint_only=True)
            calling_mind = calling.gen_mermaid_mind_map(max_display_depth=7)

            if len(calling.graph) > 5 or args.include:
                print(f"Processing {f.getName(True)}:\t\t\t\tcalling: {len(calling.graph)} {calling.max_depth} called: {len(called.graph)} {called.max_depth}")

                file_name = re.sub(r'[^\w_. -]', '_', f.getName())
                file_name = file_name[:100]  #truncate
                
                if len(calling.graph) < 300 and len(called.graph) < 600:                
                    # print(calling_flow)
                    # print(calling_mind)
                    # print(calling.get_endpoints())

                    # print(called_flow)
                    # print(called_mind)
                    # print(called.get_endpoints())

                    graph_path = output_path / Path(file_name + '.flow.md')
                    mind_path = output_path / Path(file_name + '.mind.md')                
                    #graph_path.write_text(_wrap_mermaid(calling_flow_ends))
                    graph_path.write_text(gen_callgraph_md(f,called_flow,calling_flow,calling_flow_ends,called_flow_ends, called_mind, calling_mind))
                    # graph_path.write_text(_wrap_mermaid(calling_flow) + '\n' + _wrap_mermaid(called_flow))
                    mind_path.write_text(_wrap_mermaid(calling_mind) + '\n' + _wrap_mermaid(called_mind))                            
                else:
                    # too big for demo
                    print(f"Skipping {f.getName(True)}:\t\t\t\tcalling: {len(calling.graph)} {calling.max_depth} called: {len(called.graph)} {called.max_depth}")