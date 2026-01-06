#!/usr/bin/env python3
"""
Script to multiprocess directory decompilation.

This script runs ghidrecomp on multiple binaries in parallel
to improve throughput when processing many files.
"""

from pathlib import Path
import argparse
import json
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from subprocess import STDOUT, call


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description='Multiprocess directory decompilation',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument('dir_path', help='Directory of binaries to decompile')
    parser.add_argument(
        '--proc-limit', 
        help='Concurrent process limit', 
        type=int, 
        default=2
    )
    parser.add_argument(
        '--dry-run',
        help='Show commands without executing them',
        action='store_true'
    )
    
    args = parser.parse_args()
    
    dir_path = Path(args.dir_path)
    
    if not dir_path.exists() or not dir_path.is_dir():
        print(f"Error: Directory {dir_path} does not exist or is not a directory")
        return 1
    
    # Find all files in directory (no recursive search for safety)
    file_paths = [f for f in dir_path.glob('*') if f.is_file()]
    
    if not file_paths:
        print(f"No files found in {dir_path}")
        return 0
    
    print(f"Found {len(file_paths)} files to process")
    
    # Setup logging
    log_path = Path('decomp_logs')
    if log_path.exists():
        shutil.rmtree(log_path)
    log_path.mkdir(exist_ok=True)
    
    # Prepare tasks
    log_paths = []
    for file_path in file_paths:
        file_log_path = log_path / f'{file_path.name}.log'
        cmd = ['ghidrecomp', '--va', str(file_path)]
        log_paths.append((file_log_path, cmd))
    
    # Execute tasks
    with ThreadPoolExecutor(max_workers=args.proc_limit) as executor:
        if args.dry_run:
            print("Dry run - commands that would be executed:")
            for file_log_path, cmd in log_paths:
                print(f"  {cmd} > {file_log_path}")
            return 0
        
        print(f"Processing {len(file_paths)} files with {args.proc_limit} workers...")
        
        # Submit all tasks
        future_to_file = {
            executor.submit(call, cmd, stdout=file_log_path.open('w'), stderr=STDOUT): file_path
            for file_log_path, cmd in log_paths
        }
        
        # Wait for completion and report results
        completed = 0
        for future in as_completed(future_to_file):
            file_path = future_to_file[future]
            try:
                result = future.result()
                completed += 1
                print(f"[{completed}/{len(file_paths)}] Completed: {file_path.name}")
            except Exception as e:
                print(f"[{completed}/{len(file_paths)}] Failed: {file_path.name} - {e}")
        
        print(f"Processing complete. {completed}/{len(file_paths)} files processed successfully")
        print(f"Logs available in: {log_path}")
        
        return 0 if completed == len(file_paths) else 1


if __name__ == "__main__":
    exit(main())