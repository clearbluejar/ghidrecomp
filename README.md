# Ghidrecomp - Command Line Ghidra Decompiler 

<p align="center">
<img align="center" src="https://img.shields.io/github/stars/clearbluejar/ghidrecomp?style=for-the-badge">
<a href="https://twitter.com/clearbluejar"><img align="center" src="https://img.shields.io/twitter/follow/clearbluejar?color=blue&style=for-the-badge"></a> 
<img align="center" alt="Mastodon Follow" src="https://img.shields.io/mastodon/follow/109396299069714193?color=purple&domain=https%3A%2F%2Finfosec.exchange&label=%40clearbluejar%40infosec.exchange&style=for-the-badge">
</p>

## About

This tool decompiles all the functions of a binary and writes them to a directory. The main purpose for this is to use the decomplilations for research and analysis.

## Features

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
- Specify the pdb for the binary
- Filter functions that match regex (`--filter`)

## Installation

1. [Download](https://github.com/NationalSecurityAgency/ghidra/releases) and [install Ghidra](https://htmlpreview.github.io/?https://github.com/NationalSecurityAgency/ghidra/blob/stable/GhidraDocs/InstallationGuide.html#Install).
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

Don't want to install Ghidra and Java on your host?  Use the [.devcontainer](.devcontainer) in this repo. If you don't know how, follow the detailed instructions here: [ghidra-python-vscode-devcontainer-skeleton quick setup](https://github.com/clearbluejar/ghidra-python-vscode-devcontainer-skeleton#quick-start-setup---dev-container--best-option).


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


## Sample Usage:

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