__version__ = '0.5.9'
__author__ = 'clearbluejar'

# Expose API
from .decompile import decompile
from .parser import get_parser
from .callgraph import CallGraph, get_calling, get_called, gen_callgraph
from .sast import check_tools, run_semgrep_scan, run_codeql_scan, merge_sarif_files, generate_sast_summary, preprocess_c_files

__all__ = ["get_parser", "decompile", "CallGraph", "get_calling", "get_called", "gen_callgraph", "check_tools", "run_semgrep_scan", "run_codeql_scan", "merge_sarif_files", "generate_sast_summary", "preprocess_c_files"]
