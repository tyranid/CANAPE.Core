# CANAPE.Core - (c) James Forshaw 2017
A network proxy library written in C# for .NET Core based on CANAPE. Licensed under GPLv3.

It should work on any platform with .NET Standard support 1.5, so .NET Core 1.0.4 on Windows, Linux and
macOS should be suitable as well as recompiling for .NET framework and Mono.

To use either compile with Visual Studio 2017 with .NET Core support or from the command line do the 
following:

```cd CANAPE.Core
dotnet restore
dotnet build CANAPE.Cli/CANAPE.Cli.csproj -c Release -f netcoreapp1.1
cd CANAPE.Cli/bin/Release/netcoreapp1.1
dotnet exec CANAPE.Cli.dll Examples/SocksProxy.csx --color
```
