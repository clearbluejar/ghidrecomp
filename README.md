# Ghidrecomp - Command Line Ghidra Decompiler 

<p align="center">
<img align="center" src="https://img.shields.io/github/stars/clearbluejar/ghidrecomp?style=for-the-badge">
<a href="https://twitter.com/clearbluejar"><img align="center" src="https://img.shields.io/twitter/follow/clearbluejar?color=blue&style=for-the-badge"></a> 
<img align="center" alt="Mastodon Follow" src="https://img.shields.io/mastodon/follow/109396299069714193?color=purple&domain=https%3A%2F%2Finfosec.exchange&label=%40clearbluejar%40infosec.exchange&style=for-the-badge">
</p>

## About

This Python command line tool decompiles all functions of a binary and writes them to a directory in separate `C` files:

```mermaid
flowchart LR

a(filename ) --> b[ghidrecomp]
a2[(Symbol Server)] --> b

b --> e(Ghidra Project Files)
b --> decompilations 

subgraph decompilations
    direction LR
    i(func1.c)
    h(func2.c)
    f(func3.c)
end

```


Or a single file `C` and header file with `--cppexport`:


```mermaid
flowchart LR

a(filename ) --> b[ghidrecomp]
a2[(Symbol Server)] --> b

b --> e(Ghidra Project Files)

b --> singlefile 


subgraph singlefile
  direction LR
  s1(all_funcs.c)
  s2(all_funcs.h)
end


```

The main purpose for this is to use the decomplilations for research and analysis. The tool relies on [Ghidra](https://ghidra-sre.org/) for decompilation and communicates to Ghidra with `jpype` via `pyhidra`.

## TOC

- [Ghidrecomp - Command Line Ghidra Decompiler](#ghidrecomp---command-line-ghidra-decompiler)
  - [About](#about)
  - [TOC](#toc)
  - [Features](#features)
  - [Usage](#usage)
  - [Example Usage with Windows afd.sys:](#example-usage-with-windows-afdsys)
    - [Command line](#command-line)
    - [Output](#output)
    - [Decompilation Output Dir](#decompilation-output-dir)
  - [Example usage in Docker container](#example-usage-in-docker-container)
    - [Command (Host)](#command-host)
    - [Command (in container)](#command-in-container)
    - [Output](#output-1)
    - [Decompilation Output Dir](#decompilation-output-dir-1)
  - [Installation](#installation)
    - [Windows](#windows)
    - [Linux / Mac](#linux--mac)
    - [Devcontainer / Docker](#devcontainer--docker)
      - [Option 1 - Devcontainer](#option-1---devcontainer)
      - [Option 2 - Docker](#option-2---docker)


## Features
*all these features are ultimately provided by Ghidra*

- Decompile all the functions (threaded)
  - to a folder (`-o OUTPUT_PATH`)
  - to a single c file and header file (`--cppexport`)
- Auto-downloaded symbols for supported symbol servers (`-s SYMBOLS_PATH`)
  - https://msdl.microsoft.com/download/symbols/
  - https://chromium-browser-symsrv.commondatastorage.googleapis.com/
  - https://symbols.mozilla.org/
  - https://software.intel.com/sites/downloads/symbols/
  - https://driver-symbols.nvidia.com/
  - https://download.amd.com/dir/bin/
- Specify the pdb for the binary (`--sym-file-path`)
- Filter functions to decompile that match regex (`--filter`)
- Apply custom data types (`--gdt`)

## Usage

```
usage: ghidrecomp [-h] [--cppexport] [--filter FILTERS] [--project-path PROJECT_PATH] [-o OUTPUT_PATH] [--sym-file-path SYM_FILE_PATH | -s SYMBOLS_PATH | --skip-symbols]
                  [-t THREAD_COUNT] [--va]
                  bin

ghidrecomp - A Command Line Ghidra Decompiler

positional arguments:
  bin                   Path to binary used for analysis

options:
  -h, --help            show this help message and exit
  --cppexport           Use Ghidras CppExporter to decompile to single file (default: False)
  --filter FILTERS      Regex match for function name (default: None)
  --project-path PROJECT_PATH
                        Path to base ghidra projects (default: .ghidra_projects)
  -o OUTPUT_PATH, --output-path OUTPUT_PATH
                        Location for all decompilations (default: decompilations)
  --sym-file-path SYM_FILE_PATH
                        Specify single pdb symbol file for bin (default: None)
  -s SYMBOLS_PATH, --symbols-path SYMBOLS_PATH
                        Path for local symbols directory (default: .symbols)
  --skip-symbols        Do not apply symbols (default: False)
  -t THREAD_COUNT, --thread-count THREAD_COUNT
                        Threads to use for processing. Defaults to cpu count (default: 8)
  --va                  Enable verbose analysis (default: False)
```


## Example Usage with Windows afd.sys:

### Command line
```bash
wget https://msdl.microsoft.com/download/symbols/afd.sys/50989142a9000/afd.sys -o tests/data/afd.sys.10.0.22621.1415
ghidrecomp tests/data/afd.sys.10.0.22621.1415
```

### Output
```bash
Starting decompliations: Namespace(bin='tests/data/afd.sys.10.0.22621.1344', cppexport=False, filters=None, project_path='.ghidra_projects', output_path='decompilations', sym_file_path=None, symbols_path='.symbols', skip_symbols=False, thread_count=8, va=False)
INFO  Using log config file: jar:file:/ghidra/Ghidra/Framework/Generic/lib/Generic.jar!/generic.log4j.xml (LoggingInitialization)  
INFO  Using log file: /home/vscode/.ghidra/.ghidra_10.2.3_PUBLIC/application.log (LoggingInitialization)  
INFO  Loading user preferences: /home/vscode/.ghidra/.ghidra_10.2.3_PUBLIC/preferences (Preferences)  
INFO  Class search complete (766 ms) (ClassSearcher)  
INFO  Initializing SSL Context (SSLContextInitializer)  
INFO  Initializing Random Number Generator... (SecureRandomFactory)  
INFO  Random Number Generator initialization complete: NativePRNGNonBlocking (SecureRandomFactory)  
INFO  Trust manager disabled, cacerts have not been set (ApplicationTrustManagerFactory)  
INFO  Creating project: /workspaces/ghidrecomp/.ghidra_projects/afd.sys.10.0.22621.1344/afd.sys.10.0.22621.1344 (DefaultProject)  
INFO  Using Loader: Portable Executable (PE) (AutoImporter)  
Setting up Symbol Server for symbols...
path: .symbols level: 1
Loaded well known /ghidra/Ghidra/Configurations/Public_Release/data/PDB_SYMBOL_SERVER_URLS.pdburl' length: 883'
Symbol Server Configured path: SymbolServerService:
        symbolStore: LocalSymbolStore: [ rootDir: /workspaces/ghidrecomp/.symbols, storageLevel: -1],
        symbolServers:
                HttpSymbolServer: [ url: https://msdl.microsoft.com/download/symbols/, storageLevel: -1]
                HttpSymbolServer: [ url: https://chromium-browser-symsrv.commondatastorage.googleapis.com/, storageLevel: -1]
                HttpSymbolServer: [ url: https://symbols.mozilla.org/, storageLevel: -1]
                HttpSymbolServer: [ url: https://software.intel.com/sites/downloads/symbols/, storageLevel: -1]
                HttpSymbolServer: [ url: https://driver-symbols.nvidia.com/, storageLevel: -1]
                HttpSymbolServer: [ url: https://download.amd.com/dir/bin/, storageLevel: -1]
Analyzing program afd.sys.10.0.22621.1344
INFO  PDB analyzer parsing file: /workspaces/ghidrecomp/.symbols/afd.pdb/14FBAE3662AD9F7B9D33AA9228D2554A1/afd.pdb (PdbUniversalAnalyzer)  
INFO  Resolve time: 0 mS (DefaultPdbApplicator)  
INFO  resolveCount: 0 (DefaultPdbApplicator)  
INFO  PDB Terminated Normally (DefaultPdbApplicator)  
WARN  Decompiling 1c0001340, pcode error at 1c000000c: Unable to resolve constructor at 1c000000c (DecompileCallback)  
INFO  Packed database cache: /tmp/vscode-Ghidra/packed-db-cache (PackedDatabaseCache)  
WARN  Decompiling 1c0001340, pcode error at 1c000000c: Unable to resolve constructor at 1c000000c (DecompileCallback)  
INFO  -----------------------------------------------------
    ASCII Strings                              0.343 secs
    Apply Data Archives                        0.548 secs
    Call Convention ID                         0.025 secs
    Call-Fixup Installer                       0.013 secs
    Create Address Tables                      0.039 secs
    Create Address Tables - One Time           0.076 secs
    Create Function                            0.232 secs
    Data Reference                             0.126 secs
    Decompiler Parameter ID                   10.939 secs
    Decompiler Switch Analysis                 0.442 secs
    Demangler Microsoft                        0.089 secs
    Disassemble                                0.007 secs
    Disassemble Entry Points                   1.959 secs
    Disassemble Entry Points - One Time        0.005 secs
    Embedded Media                             0.020 secs
    External Entry References                  0.000 secs
    Function ID                                0.805 secs
    Function Start Search                      0.038 secs
    Non-Returning Functions - Discovered       0.132 secs
    Non-Returning Functions - Known            0.012 secs
    PDB Universal                              2.810 secs
    Reference                                  0.104 secs
    Scalar Operand References                  0.601 secs
    Shared Return Calls                        0.219 secs
    Stack                                      5.164 secs
    Subroutine References                      0.113 secs
    Subroutine References - One Time           0.026 secs
    Windows x86 PE Exception Handling          0.027 secs
    Windows x86 PE RTTI Analyzer               0.005 secs
    Windows x86 Thread Environment Block (TEB) Analyzer     0.038 secs
    WindowsResourceReference                   0.124 secs
    x86 Constant Reference Analyzer            5.755 secs
-----------------------------------------------------
     Total Time   30 secs
-----------------------------------------------------
 (AutoAnalysisManager)  
Decompiling 1275 functions using 8 threads
Setup 8 decompliers
WARN  Decompiling 1c0001340, pcode error at 1c000000c: Unable to resolve constructor at 1c000000c (DecompileCallback)  
Completed 100 and 7%
Completed 200 and 15%
Completed 300 and 23%
Completed 400 and 31%
Completed 500 and 39%
Completed 600 and 47%
Completed 700 and 54%
Completed 800 and 62%
Completed 900 and 70%
Completed 1000 and 78%
Completed 1100 and 86%
Completed 1200 and 94%
Decompiled 1275 functions for afd.sys.10.0.22621.1344 in 13.469883680343628
Wrote 1275 decompilations for afd.sys.10.0.22621.1344 to decompilations/afd.sys.10.0.22621.1344 in 3.174959659576416
```

### Decompilation Output Dir
```bash
$ ls decompilations/afd.sys.10.0.22621.1415/
 AFDETW_NRT_TRACE-1c0034128.c                              AfdReceiveDatagramProbeAndLockPages-1c000219c.c         FUN_1c0002920-1c0002920.c
 AFDETW_RIO_TRACE_BUFFER_CLEANUP-1c0046d84.c               AfdReceiveDatagramUnlockPages-1c0016994.c               FUN_1c0003f7f-1c0003f7f.c
 AFDETW_RIO_TRACE_BUFFER_DEREGISTER-1c0046e30.c            AfdReceiveEventHandler-1c003a380.c                      FUN_1c0004001-1c0004001.c
 AFDETW_RIO_TRACE_BUFFER_REGISTER-1c0046ec4.c              AfdReceiveExpeditedEventHandler-1c003a590.c             FUN_1c000400e-1c000400e.c
 AFDETW_RIO_TRACE_CQ_CLEANUP-1c0046fec.c                   AfdRefTLBaseEndpoint-1c000ece0.c                        FUN_1c00043b4-1c00043b4.c
 AFDETW_RIO_TRACE_CQ_CLOSE-1c0047098.c                     AfdReferenceCompartment-1c000fc5c.c                     FUN_1c000468b-1c000468b.c
 AFDETW_RIO_TRACE_CQ_CREATE-1c004712c.c                    AfdReferenceEndpoint-1c001bcc4.c                        FUN_1c000726f-1c000726f.c
 AFDETW_RIO_TRACE_CQ_NOTIFY-1c00472b8.c                    AfdReferenceGroup-1c006e390.c                           FUN_1c000767a-1c000767a.c
 AFDETW_RIO_TRACE_CQ_RESIZE-1c00473c0.c                    AfdRefreshConnection-1c0032afc.c                        FUN_1c0007a11-1c0007a11.c
 AFDETW_RIO_TRACE_INVALID_BUFFERID-1c00474f4.c             AfdRefreshEndpoint-1c0032cac.c                          FUN_1c0008952-1c0008952.c
 AFDETW_RIO_TRACE_INVALID_BUFFER_RANGE-1c00475a8.c         AfdReleaseReadLockFromDpcLevel-1c001c27c.c              FUN_1c000ad2d-1c000ad2d.c
 AFDETW_RIO_TRACE_INVALID_BUFFER_SHARING-1c0047684.c       AfdReleaseRegistryHandleWait-1c006e640.c                FUN_1c000cabe-1c000cabe.c
 AFDETW_RIO_TRACE_INVALID_BUFFER_SIZE-1c0047744.c          AfdRemoveConnectionFromTimerWheel-1c0019cc0.c           FUN_1c000cc0f-1c000cc0f.c
 AFDETW_RIO_TRACE_REGDOMAIN_CLOSE-1c0047800.c              AfdRemoveEndpointFromList-1c006455c.c                   FUN_1c000cdcf-1c000cdcf.c
 AFDETW_RIO_TRACE_REGDOMAIN_CREATE-1c00478b0.c             AfdReplenishListenBacklog-1c006bad4.c                   FUN_1c000cdee-1c000cdee.c
 ```

 ```bash
 $ cat decompilations/afd.sys.10.0.22621.1415/AfdGetRemoteAddress-1c0065500.c 
```

```c
void AfdGetRemoteAddress(longlong param_1,undefined8 param_2,char param_3,undefined8 param_4,
                        undefined8 param_5,void *param_6,uint param_7,ulonglong *param_8)

{
  ushort uVar1;
  short *psVar2;
  uint uVar3;
  ulonglong uVar4;
  undefined uVar5;
  void *_Src;
  undefined8 unaff_RBX;
  undefined8 unaff_RSI;
  undefined unaff_DIL;
  char cVar7;
  ulonglong _Size;
  undefined unaff_R14B;
  undefined unaff_R15B;
  undefined unaff_retaddr;
  undefined uVar8;
  short *psVar9;
  undefined in_stack_ffffffffffffffe0;
  short *psVar6;
  
  psVar2 = *(short **)(param_1 + 0x18);
  *param_8 = 0;
  psVar6 = psVar2;
  cVar7 = param_3;
  psVar9 = psVar2;
  uVar4 = AfdLockEndpointContext((longlong)psVar2);
  uVar5 = SUB81(psVar6,0);
  uVar8 = SUB81(psVar9,0);
  if (((uVar4 != 0) && (*psVar2 == -0x502e)) && (*(char *)(psVar2 + 1) == '\x04')) {
    uVar1 = psVar2[0x5d];
    uVar5 = (undefined)uVar1;
    uVar3 = (uint)(ushort)psVar2[0x5c] + (uint)uVar1;
    if (uVar3 < *(uint *)(psVar2 + 0x74) || uVar3 == *(uint *)(psVar2 + 0x74)) {
      if (uVar1 <= param_7) {
        if (param_3 != '\0') {
          ProbeForWrite(param_6,uVar1,1);
        }
        _Size = (ulonglong)(ushort)psVar2[0x5d];
        _Src = (void *)((ushort)psVar2[0x5c] + uVar4);
        memcpy(param_6,_Src,_Size);
        *param_8 = (ulonglong)*(uint *)(psVar2 + 0x74);
        FUN_1c00655e1((char)param_6,(char)_Src,(char)_Size,(undefined)param_4,
                      in_stack_ffffffffffffffe0,unaff_R15B,unaff_R14B,unaff_DIL,unaff_retaddr,uVar8,
                      unaff_RBX,unaff_RSI);
        return;
      }
      FUN_1c00655e1(uVar5,(undefined)param_2,cVar7,(undefined)param_4,in_stack_ffffffffffffffe0,
                    unaff_R15B,unaff_R14B,unaff_DIL,unaff_retaddr,uVar8,unaff_RBX,unaff_RSI);
      return;
    }
  }
  FUN_1c00655e1(uVar5,(undefined)param_2,cVar7,(undefined)param_4,in_stack_ffffffffffffffe0,
                unaff_R15B,unaff_R14B,unaff_DIL,unaff_retaddr,uVar8,unaff_RBX,unaff_RSI);
  return;
}
```

## Example usage in Docker container


### Command (Host)
```bash
$ docker run --user vscode  --rm -it ghcr.io/clearbluejar/ghidrecomp:latest bash
Unable to find image 'ghcr.io/clearbluejar/ghidrecomp:latest' locally
latest: Pulling from clearbluejar/ghidrecomp
32fb02163b6b: Pull complete
167c7feebee8: Pull complete
d6dfff1f6f3d: Pull complete
e9cdcd4942eb: Pull complete
ca3bce705f6c: Pull complete
5e1c6c4f8bbf: Pull complete
e7e563b10921: Pull complete
9eb9d866c104: Pull complete
8ca602e7301a: Pull complete
124a51dde68b: Pull complete
c04919d34655: Pull complete
a2570739af5d: Pull complete
e57c67fabbc5: Pull complete
8da6a860f9e3: Pull complete
ca6008c09918: Pull complete
702a3b20cdb3: Pull complete
bd0b7bd152dc: Pull complete
7299f2e2483b: Pull complete
4f4fb700ef54: Pull complete
7cbbb1896fad: Pull complete
1f309d93fb79: Pull complete
d11b50be43c4: Pull complete
7c66f674c44d: Pull complete
8497280f5c51: Pull complete
Digest: sha256:4e42285dc1d71c849b7c89fae6598691bdc7d0ee9ec55eb70ce00b5c722fba59
Status: Downloaded newer image for ghcr.io/clearbluejar/ghidrecomp:latest
```

### Command (in container)
```bash
vscode ➜ / $ pip install ghidrecomp
vscode ➜ / $ cd /tmp/
vscode ➜ /tmp $ ghidrecomp /bin/ls
```

### Output
```bash
Starting decompliations: Namespace(bin='/bin/ls', cppexport=False, filters=None, project_path='.ghidra_projects', output_path='decompilations', sym_file_path=None, symbols_path='.symbols', skip_symbols=False, thread_count=12, va=False)
INFO  Using log config file: jar:file:/ghidra/Ghidra/Framework/Generic/lib/Generic.jar!/generic.log4j.xml (LoggingInitialization)
INFO  Using log file: /home/vscode/.ghidra/.ghidra_10.2.3_PUBLIC/application.log (LoggingInitialization)
INFO  Loading user preferences: /home/vscode/.ghidra/.ghidra_10.2.3_PUBLIC/preferences (Preferences)
INFO  Class search complete (898 ms) (ClassSearcher)
INFO  Initializing SSL Context (SSLContextInitializer)
INFO  Initializing Random Number Generator... (SecureRandomFactory)
INFO  Random Number Generator initialization complete: NativePRNGNonBlocking (SecureRandomFactory)
INFO  Trust manager disabled, cacerts have not been set (ApplicationTrustManagerFactory)
INFO  Creating project: /tmp/.ghidra_projects/ls/ls (DefaultProject)
INFO  Starting cache cleanup: /tmp/vscode-Ghidra/fscache2 (FileCacheMaintenanceDaemon)
INFO  Finished cache cleanup, estimated storage used: 0 (FileCacheMaintenanceDaemon)
INFO  Using Loader: Executable and Linking Format (ELF) (AutoImporter)
Setting up Symbol Server for symbols...
path: .symbols level: 1
Loaded well known /ghidra/Ghidra/Configurations/Public_Release/data/PDB_SYMBOL_SERVER_URLS.pdburl' length: 883'
Symbol Server Configured path: SymbolServerService:
        symbolStore: LocalSymbolStore: [ rootDir: /tmp/.symbols, storageLevel: -1],
        symbolServers:
                HttpSymbolServer: [ url: https://msdl.microsoft.com/download/symbols/, storageLevel: -1]
                HttpSymbolServer: [ url: https://chromium-browser-symsrv.commondatastorage.googleapis.com/, storageLevel: -1]
                HttpSymbolServer: [ url: https://symbols.mozilla.org/, storageLevel: -1]
                HttpSymbolServer: [ url: https://software.intel.com/sites/downloads/symbols/, storageLevel: -1]
                HttpSymbolServer: [ url: https://driver-symbols.nvidia.com/, storageLevel: -1]
                HttpSymbolServer: [ url: https://download.amd.com/dir/bin/, storageLevel: -1]
Analyzing program ls
INFO  DWARF external debug information found: ExternalDebugInfo [filename=61a544c35b9dc1d172d1a1c09043e487326966.debug, crc=d165fd8a, hash=6461a544c35b9dc1d172d1a1c09043e487326966] (ExternalDebugFilesService)
INFO  Unable to find DWARF information, skipping DWARF analysis (DWARFAnalyzer)
INFO  hit non-returning function, restarting decompiler switch analyzer later (DecompilerSwitchAnalyzer)
INFO  Packed database cache: /tmp/vscode-Ghidra/packed-db-cache (PackedDatabaseCache)
INFO  -----------------------------------------------------
    ASCII Strings                              0.565 secs
    Apply Data Archives                        0.462 secs
    Call Convention ID                         0.013 secs
    Call-Fixup Installer                       0.009 secs
    Create Address Tables                      0.077 secs
    Create Address Tables - One Time           0.025 secs
    Create Function                            0.036 secs
    DWARF                                      0.011 secs
    Data Reference                             0.054 secs
    Decompiler Switch Analysis                 0.136 secs
    Decompiler Switch Analysis - One Time      2.743 secs
    Demangler GNU                              0.044 secs
    Disassemble Entry Points                   1.104 secs
    ELF Scalar Operand References              0.285 secs
    Embedded Media                             0.011 secs
    External Entry References                  0.000 secs
    Function ID                                0.225 secs
    Function Start Search                      0.033 secs
    Function Start Search After Code           0.012 secs
    Function Start Search After Data           0.012 secs
    GCC Exception Handlers                     0.319 secs
    Non-Returning Functions - Discovered       0.189 secs
    Non-Returning Functions - Known            0.005 secs
    Reference                                  0.129 secs
    Shared Return Calls                        0.092 secs
    Stack                                      1.734 secs
    Subroutine References                      0.048 secs
    Subroutine References - One Time           0.000 secs
    x86 Constant Reference Analyzer            2.017 secs
-----------------------------------------------------
     Total Time   10 secs
-----------------------------------------------------
 (AutoAnalysisManager)
Skipped 0 functions that failed to match any of None
Decompiling 520 functions using 12 threads
Setup 12 decompliers
Completed 100 and 19%
Completed 200 and 38%
Completed 300 and 57%
WARN  Decompiling 00126010, pcode error at 00126010: Unable to disassemble EXTERNAL block location: 00126010 (DecompileCallback)

Decompiled 520 functions for ls in 5.361317157745361
Wrote 520 decompilations for ls to decompilations/ls in 0.1671760082244873
```


### Decompilation Output Dir

```bash
vscode ➜ /tmp $ ls decompilations/ls/
FUN_00104020-00104020.c  FUN_00108e10-00108e10.c  FUN_0010fc80-0010fc80.c  FUN_00116ef0-00116ef0.c                 bindtextdomain-001260d8.c   mbstowcs-00104150.c
FUN_001046e0-001046e0.c  FUN_00108eb0-00108eb0.c  FUN_0010fd60-0010fd60.c  FUN_001173b0-001173b0.c                 calloc-00104390.c           mbstowcs-00126098.c
FUN_001046e5-001046e5.c  FUN_00108fa0-00108fa0.c  FUN_0010fee0-0010fee0.c  FUN_00117430-00117430.c                 calloc-001261c0.c           memcmp-00104360.c
FUN_001046ea-001046ea.c  FUN_001093a0-001093a0.c  FUN_00110180-00110180.c  FUN_001174b0-001174b0.c                 caseD_b-00104712.c          memcmp-001261a8.c
FUN_001046ef-001046ef.c  FUN_00109850-00109850.c  FUN_001101e0-001101e0.c  FUN_00117530-00117530.c                 clock_gettime-00104170.c    memcpy-00104410.c
...
```

```bash
 cat decompilations/ls/FUN_0010eb20-0010eb20.c
```
```c
void * FUN_0010eb20(void *param_1,char *param_2,void **param_3)

{
  size_t __n;
  long lVar1;
  long lVar2;
  size_t __n_00;
  void *__dest;
  undefined *puVar3;
  ulong uVar4;
  undefined local_41;

  lVar1 = FUN_0010e740();
  lVar2 = FUN_0010e7a0(lVar1);
  __n = (lVar1 - (long)param_1) + lVar2;
  __n_00 = strlen(param_2);
  if (lVar2 == 0) {
    local_41 = 0x2e;
    if (*param_2 != '/') {
      local_41 = 0;
    }
    uVar4 = (ulong)(*param_2 == '/');
  }
  else if (*(char *)((long)param_1 + (__n - 1)) == '/') {
    local_41 = 0;
    uVar4 = 0;
  }
  else {
    local_41 = 0x2f;
    if (*param_2 == '/') {
      local_41 = 0;
    }
    uVar4 = (ulong)(*param_2 != '/');
  }
  __dest = malloc(__n + 1 + __n_00 + uVar4);
  if (__dest != (void *)0x0) {
    puVar3 = (undefined *)mempcpy(__dest,param_1,__n);
    *puVar3 = local_41;
    if (param_3 != (void **)0x0) {
      *param_3 = puVar3 + uVar4;
    }
    puVar3 = (undefined *)mempcpy(puVar3 + uVar4,param_2,__n_00);
    *puVar3 = 0;
  }
  return __dest;
}
```

## Installation

1. [Download](https://github.com/NationalSecurityAgency/ghidra/releases) and [install Ghidra](https://htmlpreview.github.io/?https://github.com/NationalSecurityAgency/ghidra/blob/stable/GhidraDocs/InstallationGuide.html#Install) and [Java](https://htmlpreview.github.io/?https://github.com/NationalSecurityAgency/ghidra/blob/stable/GhidraDocs/InstallationGuide.html#JavaNotes) required for Ghidra.
2. Set Ghidra Environment Variable `GHIDRA_INSTALL_DIR` to Ghidra install location.
3. Pip install `ghidrecomp`

### Windows

```powershell
PS C:\Users\user> [System.Environment]::SetEnvironmentVariable('GHIDRA_INSTALL_DIR','C:\ghidra_10.2.3_PUBLIC_20230208\ghidra_10.2.3_PUBLIC')
PS C:\Users\user> pip install ghidrecomp
```
### Linux / Mac

```bash
export GHIDRA_INSTALL_DIR="/path/to/ghidra/"
pip install ghidrecomp
```

### Devcontainer / Docker

Avoid installing Ghidra and Java on your host by using a **devcontainer**. 

#### Option 1 - Devcontainer
Use the [.devcontainer](.devcontainer) in this repo. If you don't know how, follow the detailed instructions here: [ghidra-python-vscode-devcontainer-skeleton quick setup](https://github.com/clearbluejar/ghidra-python-vscode-devcontainer-skeleton#quick-start-setup---dev-container--best-option).

#### Option 2 - Docker

Use the published repo image with Ghidra and Java already installed.

```bash
docker pull ghcr.io/clearbluejar/ghidrecomp:latest
docker run --user vscode  --rm -it ghcr.io/clearbluejar/ghidrecomp:latest bash
```

From within the image:
```bash
vscode ➜ / $ uname -a
Linux 4da2fe33369a 5.15.49-linuxkit #1 SMP PREEMPT Tue Sep 13 07:51:32 UTC 2022 x86_64 GNU/Linux
vscode ➜ / $ ls /ghidra/
Extensions  GPL  Ghidra  LICENSE  bom.json  docs  ghidraRun  ghidraRun.bat  licenses  server  support
vscode ➜ / $ pip install ghidrecomp
Successfully installed Jpype1-1.4.1 ghidrecomp-0.1.0 packaging-23.0 pyhidra-0.4.1
```


