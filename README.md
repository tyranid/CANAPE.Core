# CANAPE.Core - (c) James Forshaw 2017
A network proxy library written in C# for .NET Core based on CANAPE. Licensed under GPLv3.

It should work on any platform with .NET Standard support 2.0, so .NET Core 7.0 and .NET Framework 4.8 on Windows, Linux and
macOS should be suitable as well as recompiling for .NET framework and Mono.

To use either compile with Visual Studio 2022 with .NET Core support or from the command line do the 
following:

```cd CANAPE.Core
dotnet build CANAPE.Cli/CANAPE.Cli.csproj -c Release -f netcoreapp7.0
cd CANAPE.Cli/bin/Release/netcoreapp7.0
dotnet exec CANAPE.Cli.dll Examples/SocksProxy.csx --color
```