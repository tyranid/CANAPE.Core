# CANAPE.Core - (c) James Forshaw 2017
A network proxy library written in C# for .NET Core based on CANAPE. Licensed under GPLv3.

# Build 

## On your host
It should work on any platform with .NET Standard support 2.0, so .NET Core 2.0.5 and .NET Framework 4.7.1 on Windows, Linux and
macOS should be suitable as well as recompiling for .NET framework and Mono.

To use either compile with Visual Studio 2017 with .NET Core support or from the command line do the 
following:

``` bash
$ cd CANAPE.Core
$ dotnet restore
$ dotnet build CANAPE.Cli/CANAPE.Cli.csproj -c Release -f netcoreapp2.0
$ cd CANAPE.Cli/bin/Release/netcoreapp2.0
$ dotnet exec CANAPE.Cli.dll Examples/SocksProxy.csx --color
```

## With Docker

```bash 
$ cat << EOF > build.sh
#!/usr/bin/env bash

dotnet restore *.sln &&\
    dotnet publish CANAPE.Cli/CANAPE.Cli.csproj -c Release -f netcoreapp2.0 --self-contained \
    -r linux-x64 
#    -r win10-x64 
#    -r osx.10.13-x64
# Chose the runtime ID that you need (you can only chose one per build)
# More info on supported RIDs (some RIDs like osx.10.14-x86 are not supported yet) :
# https://github.com/dotnet/corefx
# https://docs.microsoft.com/en-us/dotnet/core/rid-catalog
EOF
$ chmod 755 build.sh
$ sudo docker run --rm -v $(pwd):/canape -it mcr.microsoft.com/dotnet/core/sdk:2.2 \
    /bin/bash -c 'cd canape && ./build.sh'
```
# Usage

``` bash
$ ./CANAPE.Cli -h
CANAPE.Cli (c) 2017 James Forshaw, 2014 Context Information Security.
Usage:  [arguments] [options]

Arguments:
  script            Specify a script file to run.

Options:
  -c | --compile    Compile script file only.
  -v | --verbose    Enable verbose logging output.
  -i | --include    Specify additional include directories to be accessed via the #load directive.
  -l | --libs       Specify additional library directories to be accessed via the #r directive.
  --color           Enable ANSI 24 bit color output (if supported).
  -? | -h | --help  Show help information
```

