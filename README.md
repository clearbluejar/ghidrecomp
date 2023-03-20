# Ghidrecomp - Command Line Ghidra Decompiler 

<p align="center">
<img align="center" src="">
</p>

<p align="center">
<img align="center" src="https://img.shields.io/github/stars/clearbluejar/ghidrecomp?style=for-the-badge">
<a href="https://twitter.com/clearbluejar"><img align="center" src="https://img.shields.io/twitter/follow/clearbluejar?color=blue&style=for-the-badge"></a> 
<img align="center" alt="Mastodon Follow" src="https://img.shields.io/mastodon/follow/109396299069714193?color=purple&domain=https%3A%2F%2Finfosec.exchange&label=%40clearbluejar%40infosec.exchange&style=for-the-badge">
</p>

## About

This tool decompiles all the functions of a binary and writes them to a directory. The main purpose for this is to use the decomplilations for research and analysis.

## Features

- Decompile all the functions within a binary (threaded)
- Hook for extra_processing
- Dump

## Usage

```
usage: decompile-all-the-things.py [-h] [-s SYMBOL_PATH] [--sym-file-path SYM_FILE_PATH] [-o OUTPUT_PATH] [--project-path PROJECT_PATH] bin

A demo Ghidra callgraph generation script

positional arguments:
  bin                   Path to binary used for analysis

options:
  -h, --help            show this help message and exit
  -s SYMBOL_PATH, --symbol-path SYMBOL_PATH
                        Path to symbol path for bin
  --sym-file-path SYM_FILE_PATH
                        Specify pdb symbol file for bin
  -o OUTPUT_PATH, --output-path OUTPUT_PATH
                        Location for all decompilations
  --project-path PROJECT_PATH
                        Path to base ghidra projects
```


## Sample Output:

```bash
python decompile-all-the-things.py bins/ntoskrnl.exe.x64.10.0.22000.1335
```
```bash
Namespace(bin='bins/ntoskrnl.exe.x64.10.0.22000.1335', symbol_path='.symbols', sym_file_path=None, output_path='.decompilations', project_path='.ghidra_projects')
INFO  Using log config file: jar:file:/ghidra/Ghidra/Framework/Generic/lib/Generic.jar!/generic.log4j.xml (LoggingInitialization)  
INFO  Using log file: /home/vscode/.ghidra/.ghidra_10.2.3_PUBLIC/application.log (LoggingInitialization)  
INFO  Loading user preferences: /home/vscode/.ghidra/.ghidra_10.2.3_PUBLIC/preferences (Preferences)  
INFO  Class search complete (824 ms) (ClassSearcher)  
INFO  Initializing SSL Context (SSLContextInitializer)  
INFO  Initializing Random Number Generator... (SecureRandomFactory)  
INFO  Random Number Generator initialization complete: NativePRNGNonBlocking (SecureRandomFactory)  
INFO  Trust manager disabled, cacerts have not been set (ApplicationTrustManagerFactory)  
INFO  Opening project: /workspaces/ghidra-decompile-all-the-things/.ghidra_projects/ntoskrnl.exe.x64.10.0.22000.1335/ntoskrnl.exe.x64.10.0.22000.1335 (DefaultProject)  
Setup 8 decompliers
Skipped 0 FUN_ functions
Decompiling 32645 functions using 8 threads
Completed 100 and 0%
Completed 200 and 0%
Completed 300 and 0%
Completed 400 and 1%
Completed 500 and 1%
Completed 600 and 1%
Completed 700 and 2%
Completed 800 and 2%
Completed 900 and 2%
Completed 1000 and 3%
Completed 1100 and 3%
Completed 1200 and 3%
Completed 1300 and 3%
Completed 1400 and 4%
Completed 1500 and 4%
Completed 1600 and 4%
Completed 1700 and 5%
Completed 1800 and 5%
Completed 1900 and 5%
Completed 2000 and 6%
Completed 2100 and 6%
Completed 2200 and 6%
Completed 2300 and 7%
WARN  Decompiling 1402f53b0, pcode error at 14000000c: Unable to resolve constructor at 14000000c (DecompileCallback)  
Completed 2400 and 7%
Completed 2500 and 7%
Completed 2600 and 7%
Completed 2700 and 8%
Completed 2800 and 8%
Completed 2900 and 8%
Completed 3000 and 9%
WARN  Decompiling 14031ebd0, pcode error at 14031efb0: Unable to resolve constructor at 14031efb0 (DecompileCallback)  
WARN  Decompiling 14031ebd0, pcode error at 14000000c: Unable to resolve constructor at 14000000c (DecompileCallback)  
Completed 3100 and 9%
Completed 3200 and 9%
Completed 7400 and 22%
Completed 7500 and 22%
Completed 7600 and 23%
<several lines omitted>
Completed 31800 and 97%
Completed 31900 and 97%
Completed 32000 and 98%
Completed 32100 and 98%
Completed 32200 and 98%
Completed 32300 and 98%
Completed 32400 and 99%
Completed 32500 and 99%
Completed 32600 and 99%
Decompiled 32645 functions for ntoskrnl.exe.x64.10.0.22000.1335 in 255.92349696159363
Wrote 32645 decompilations for ntoskrnl.exe.x64.10.0.22000.1335 to .decompilations/ntoskrnl.exe.x64.10.0.22000.1335 in 10.600381851196289
```