"""
SAST scanning module for ghidrecomp.

Provides semgrep-based static analysis scanning of decompiled code,
with placeholders for CodeQL integration.
"""

import argparse

import shutil
import subprocess
import json
import os
import sys
from pathlib import Path
from typing import List, Optional, Tuple, Callable, Any
from concurrent.futures import ThreadPoolExecutor, as_completed


def run(cmd, cwd=None, timeout=600, env=None):
    """Execute a command and return results."""
    p = subprocess.run(
        cmd,
        cwd=cwd,
        env=env or os.environ.copy(),
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    return p.returncode, p.stdout, p.stderr


def check_tools():
    """Check if required SAST tools are installed."""
    if shutil.which("semgrep") is None:
        raise RuntimeError(
            "semgrep not installed. Install via `pip install semgrep` or `pip install 'ghidrecomp[sast]'`"
        )
    # Placeholder for CodeQL check
    # if shutil.which("codeql") is None:
    #     raise RuntimeError("codeql not installed. Download from https://github.com/github/codeql-cli-binaries/releases")


def run_single_semgrep(
    configs: List[str],
    repo_path: Path,
    out_dir: Path,
    timeout: int,
    progress_callback: Optional[Callable] = None
) -> Tuple[str, bool]:
    """
    Run a single Semgrep scan with one or more configs.

    Returns:
        Tuple of (sarif_path, success)
    """
    sarif = out_dir / "semgrep.sarif"
    stderr_log = out_dir / "logs" / "semgrep.stderr.log"
    stderr_log.parent.mkdir(parents=True, exist_ok=True)
    exit_file = out_dir / "semgrep.exit"

    if progress_callback:
        progress_callback(f"Scanning with {len(configs)} config(s)")

    # Use full path to semgrep to avoid broken venv installations
    semgrep_cmd = shutil.which("semgrep")

    cmd = [
        semgrep_cmd,
        "scan",
        "--metrics=off",
        "--disable-version-check",
        "--quiet",
        "--error",
        "--sarif",
        "--timeout", str(30),  # Rule timeout
        "--no-git-ignore",
    ]
    
    # Add each config with -c flag
    for config in configs:
        cmd.extend(["-c", config])
    
    cmd.append(str(repo_path))

    # Create clean environment without venv contamination
    clean_env = os.environ.copy()
    clean_env.pop('VIRTUAL_ENV', None)
    clean_env.pop('PYTHONPATH', None)
    # Remove venv from PATH
    if 'PATH' in clean_env:
        path_parts = clean_env['PATH'].split(':')
        path_parts = [p for p in path_parts if 'venv' not in p.lower() and '/bin/pysemgrep' not in p]
        clean_env['PATH'] = ':'.join(path_parts)

    try:
        # Print the semgrep command for debugging
        print(f"Running semgrep command: {' '.join(cmd)}")
        rc, so, se = run(cmd, timeout=timeout, env=clean_env)

        # Validate output
        if not so or not so.strip():
            so = '{"runs": []}'

        sarif.write_text(so)
        stderr_log.write_text(se or "")
        exit_file.write_text(str(rc))

        # Basic validation: check if SARIF is valid JSON
        try:
            json.loads(so)
            is_valid = True
        except json.JSONDecodeError:
            is_valid = False

        success = rc in (0, 1) and is_valid

        return str(sarif), success

    except Exception as e:
        # Write empty SARIF on error
        sarif.write_text('{"runs": []}')
        stderr_log.write_text(str(e))
        exit_file.write_text("-1")
        print(f"Semgrep scan failed: {e}")
        return str(sarif), False


def preprocess_c_files(decomp_dir: Path) -> None:
    """
    Simple preprocessing of decompiled C files to remove Ghidra artifacts.
    
    Args:
        decomp_dir: Directory containing decompiled .c files to preprocess
    """
    import re
    
    # Simple cleanup patterns for calling conventions that aren't standard C
    cleanup_patterns = [
        (r'\b__stdcall\b', ''),
        (r'\b__cdecl\b', ''),
        (r'\b__thiscall\b', ''),
        (r'\b__fastcall\b', ''),
        (r'\b__vectorcall\b', ''),
        (r'\b__noreturn\b', ''),
    ]
    
    for c_file in decomp_dir.glob("*.c"):
        try:
            # Read original content
            original_content = c_file.read_text(encoding='utf-8', errors='ignore')
            original_lines = original_content.split('\n')
            
            # Apply cleanup patterns
            cleaned_content = original_content
            for pattern, replacement in cleanup_patterns:
                cleaned_content = re.sub(pattern, replacement, cleaned_content, flags=re.MULTILINE)
            
            # Ensure line count doesn't change by counting and adjusting
            cleaned_lines = cleaned_content.split('\n')
            
            # If we accidentally changed line count, fix it
            if len(cleaned_lines) != len(original_lines):
                # Add or remove empty lines to match original count
                if len(cleaned_lines) < len(original_lines):
                    cleaned_lines.extend([''] * (len(original_lines) - len(cleaned_lines)))
                elif len(cleaned_lines) > len(original_lines):
                    cleaned_lines = cleaned_lines[:len(original_lines)]
                
                cleaned_content = '\n'.join(cleaned_lines)
            
            # Write back to same file
            c_file.write_text(cleaned_content, encoding='utf-8')
            
        except Exception as e:
            print(f"Warning: Failed to preprocess {c_file}: {e}")


def run_semgrep_scan(decomp_dir: Path, rules_dirs: List[str], out_sarif: Path) -> str:
    """
    Run Semgrep scan on decompiled code.

    Args:
        decomp_dir: Directory containing decompiled .c files
        rules_dirs: List of rule directory paths (empty defaults to p/c)
        out_sarif: Output SARIF file path

    Returns:
        Path to output SARIF file
    """
    out_dir = out_sarif.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    # Default to p/c if no rules provided
    if not rules_dirs:
        rules_dirs = ["p/c"]

    # Process all rule paths - check if they exist as files/directories
    configs: List[str] = []
    for rd in rules_dirs:
        rd_path = Path(rd)
        if rd_path.exists():
            configs.append(str(rd_path))
        else:
            # Treat as pack name (e.g., p/c)
            configs.append(rd)

    # Run a single scan with all configs
    print(f"Running semgrep with configs: {configs}")
    sarif_path, success = run_single_semgrep(
        configs=configs,
        repo_path=decomp_dir,
        out_dir=out_dir,
        timeout=600
    )

    if success:
        print(f"Semgrep scan completed successfully")
        # Copy the generated SARIF to the requested output location
        if sarif_path != str(out_sarif) and Path(sarif_path).exists():
            import shutil
            shutil.copy2(sarif_path, out_sarif)
    else:
        print("Warning: Semgrep scan failed")
        # Write empty SARIF on failure
        out_sarif.write_text('{"runs": []}')

    return str(out_sarif)


def run_codeql_scan(decomp_dir: Path, rules_dirs: List[str], out_sarif: Path) -> str:
    """
    Placeholder for CodeQL scanning.

    Currently just logs a message.
    """
    print("CodeQL integration coming soon")
    # Write empty SARIF as placeholder
    out_sarif.write_text('{"runs": []}')
    return str(out_sarif)


def generate_sast_summary(sarif_paths: List[str], base_directory: Optional[str] = None) -> dict:
    """
    Generate summary statistics from SAST scan results.
    
    Args:
        sarif_paths: List of paths to SARIF files
        base_directory: Base directory that was scanned (optional)
        
    Returns:
        Dictionary containing scan metrics and statistics
    """
    import os
    from datetime import datetime
    
    # Temporary dict to track findings by file
    findings_by_file = {}
    
    # Count files scanned from filesystem if base_directory is provided
    files_scanned = 0
    if base_directory and os.path.exists(base_directory):
        files_scanned = len([f for f in Path(base_directory).glob("*.c") if f.is_file()])
    
    summary = {
        "scan_timestamp": datetime.now().isoformat(),
        "base_directory": str(Path(base_directory)) if base_directory else None,
        "total_sarif_files": len(sarif_paths),
        "total_findings": 0,
        "findings_by_severity": {
            "error": 0,
            "warning": 0, 
            "note": 0,
            "none": 0
        },
        "findings_by_rule": {},
        "top_findings": [],
        "tools_used": [],
        "files_scanned": files_scanned,
        "dataflow_paths": 0,
        "total_dataflow_steps": 0
    }
    
    for sarif_path in sarif_paths:
        if not os.path.exists(sarif_path):
            print(f"Warning: SARIF file not found: {sarif_path}")
            continue
            
        try:
            with open(sarif_path) as f:
                sarif_data = json.load(f)
        except (json.JSONDecodeError, Exception) as e:
            print(f"Warning: Failed to parse SARIF file {sarif_path}: {e}")
            continue
            
        for run in sarif_data.get("runs", []):
            # Track tool information
            tool = run.get("tool", {})
            driver = tool.get("driver", {})
            tool_name = driver.get("name", "unknown")
            if tool_name not in summary["tools_used"]:
                summary["tools_used"].append(tool_name)
            
            # Note: files_scanned is already counted from filesystem above
            # artifacts field in semgrep SARIF is typically null
            
            # Count rules executed
            rules = driver.get("rules", [])
            
            # Analyze findings
            results = run.get("results", [])
            summary["total_findings"] += len(results)
            
            for result in results:
                # Count by severity
                level = result.get("level", "warning")
                if level in summary["findings_by_severity"]:
                    summary["findings_by_severity"][level] += 1
                    
                # Count by rule
                rule_id = result.get("ruleId", "unknown")
                summary["findings_by_rule"][rule_id] = summary["findings_by_rule"].get(rule_id, 0) + 1
                
                # Count by file
                locations = result.get("locations", [])
                if locations:
                    file_path = "unknown"
                    try:
                        # Extract file path from first location
                        physical_location = locations[0].get("physicalLocation", {})
                        artifact_location = physical_location.get("artifactLocation", {})
                        file_path = artifact_location.get("uri", "unknown")
                    except (KeyError, TypeError):
                        pass
                    
                    findings_by_file[file_path] = findings_by_file.get(file_path, 0) + 1
                
                # Count dataflow paths (mainly for CodeQL)
                code_flows = result.get("codeFlows", [])
                if code_flows:
                    summary["dataflow_paths"] += 1
                    for flow in code_flows:
                        for thread_flow in flow.get("threadFlows", []):
                            locations = thread_flow.get("locations", [])
                            summary["total_dataflow_steps"] += len(locations)
    
    # Generate top findings
    n = 10  # Number of top files to show
    if findings_by_file:
        # Sort by count descending and take top n
        sorted_findings = sorted(findings_by_file.items(), key=lambda x: x[1], reverse=True)[:n]
        summary["top_findings"] = [{"file": file, "count": count} for file, count in sorted_findings]
        summary["files_with_findings"] = len([f for f, c in findings_by_file.items() if c > 0])
    else:
        summary["top_findings"] = []
        summary["files_with_findings"] = 0
    
    # Add summary statistics
    summary["rules_executed"] = len(summary["findings_by_rule"])
    
    return summary


def merge_sarif_files(output_path: str, input_paths: list) -> None:
    """Merge multiple SARIF files into one."""
    merged = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": []
    }

    for input_path in input_paths:
        try:
            with open(input_path) as f:
                sarif = json.load(f)

            # Add all runs from this SARIF
            if "runs" in sarif:
                merged["runs"].extend(sarif["runs"])

        except Exception as e:
            print(f"Warning: Failed to merge {input_path}: {e}", file=sys.stderr)
            continue

    # Write merged output
    with open(output_path, 'w') as f:
        json.dump(merged, f, indent=2)

    print(f"Merged {len(input_paths)} SARIF files into {output_path}")
    print(f"Total runs: {len(merged['runs'])}")


def add_sast_args_to_parser(parser: argparse.ArgumentParser):
    """Add SAST-related command-line arguments to the parser."""
    sast_group = parser.add_argument_group('SAST Options')
    sast_group.add_argument('--sast', action='store_true', help='Run SAST scanning on decompiled code with semgrep and CodeQL')
    sast_group.add_argument('--semgrep-rules', action='append', help='Path to local semgrep rule file or directory (can be specified multiple times, default: p/c)')
    sast_group.add_argument('--codeql-rules', help='Comma-separated paths to local CodeQL query directories (placeholder)')