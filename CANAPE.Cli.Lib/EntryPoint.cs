//    CANAPE Core Network Testing Library
//    Copyright (C) 2017 James Forshaw
//    Based in part on CANAPE Network Testing Tool
//    Copyright (C) 2014 Context Information Security
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program.  If not, see <http://www.gnu.org/licenses/>.
using CANAPE.Net.Templates;
using CANAPE.Utils;
using McMaster.Extensions.CommandLineUtils;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Scripting;
using Microsoft.CodeAnalysis.Scripting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace CANAPE.Cli
{
    public static class EntryPoint
    {
        private static string ExceptionToString(Exception ex, bool full_output)
        {
            return full_output ? ex.ToString() : ex.Message;
        }

        private static void PrintException(Exception ex, bool full_output)
        {
            if (ex is CompilationErrorException)
            {
                Console.Error.WriteLine("Compilation Failure: {0}", ExceptionToString(ex, false));
            }
            else if (ex is AggregateException)
            {
                AggregateException agg = (AggregateException)ex;
                foreach (Exception e in agg.InnerExceptions)
                {
                    PrintException(e, full_output);
                }
            }
            else
            {
                Console.Error.WriteLine("Error: {0}", ExceptionToString(ex, full_output));
            }
        }

        private static ScriptOptions CreateScriptOptions(string filename, IEnumerable<string> include_dirs, IEnumerable<string> metadata_dirs)
        {
            string base_path = Path.GetDirectoryName(typeof(EntryPoint).GetTypeInfo().Assembly.Location);
            List<string> resolve_paths = new List<string>
            {
                Directory.GetCurrentDirectory(),
                base_path
            };
            if (filename != null)
            {
                resolve_paths.Add(Path.GetDirectoryName(filename));
            }

            Type template_type = typeof(FixedProxyTemplate);
            SourceFileResolver resolver = new SourceFileResolver(include_dirs.Concat(resolve_paths), base_path);
            ScriptMetadataResolver metadata_resolver = ScriptMetadataResolver.Default
                    .WithBaseDirectory(base_path)
                    .WithSearchPaths(metadata_dirs.Concat(resolve_paths));
            return ScriptOptions.Default.WithImports(template_type.Namespace, "CANAPE", "System",
                                                     "CANAPE.Utils", "CANAPE.Nodes", "CANAPE.Net.Utils",
                                                     "CANAPE.DataFrames", "CANAPE.Net.Templates.Factories",
                                                     "CANAPE.Net.Templates", "CANAPE.Security.Cryptography.X509Certificates")
                .WithReferences(template_type.GetTypeInfo().Assembly,
                                typeof(EntryPoint).GetTypeInfo().Assembly)
                .WithSourceResolver(resolver)
                .WithMetadataResolver(metadata_resolver);
        }

        // Quick and dirty as Rosyln compiler doesn't seem to expose the same API to external
        // callers as it does for CSI. Allows for some basic block code to be used from console.
        private static int GetBraceCount(string line)
        {
            return line.Count(c => c == '{') - line.Count(c => c == '}');
        }

        private async static Task RunConsole(IEnumerable<string> include_dirs, IEnumerable<string> metadata_dirs)
        {
            var options = CreateScriptOptions(null, include_dirs, metadata_dirs);
            var state = await CSharpScript.RunAsync("static void quit() { Environment.Exit(0); }", options);
            Console.WriteLine("Type quit() to exit the console");

            while (true)
            {
                StringBuilder current_line = new StringBuilder();
                Console.Write("> ");
                do
                {
                    current_line.AppendLine(Console.ReadLine().Trim());
                }
                while (GetBraceCount(current_line.ToString()) > 0);

                try
                {
                    state = await state.ContinueWithAsync(current_line.ToString(), options);
                    if (state.ReturnValue != null)
                    {
                        Console.WriteLine(state.ReturnValue);
                    }
                }
                catch (Exception ex)
                {
                    PrintException(ex, true);
                }
            }
        }

        private static ScriptRunner<object> CompileScript(string filename,
            IEnumerable<string> include_dirs,
            IEnumerable<string> metadata_dirs)
        {
            var options = CreateScriptOptions(filename, include_dirs, metadata_dirs);
            var compiled = CSharpScript.Create(File.ReadAllText(filename), options, typeof(GlobalArgs));
            try
            {
                return compiled.CreateDelegate();
            }
            catch (Exception ex)
            {
                PrintException(ex, false);
                return null;
            }
        }

        private async static Task RunScript(string filename,
            IEnumerable<string> include_dirs,
            IEnumerable<string> metadata_dirs,
            IEnumerable<string> args)
        {
            var runner = CompileScript(filename, include_dirs, metadata_dirs);
            if (runner == null)
            {
                return;
            }
            try
            {
                await runner(new GlobalArgs(args));
            }
            catch (Exception ex)
            {
                PrintException(ex, true);
            }
        }

        [STAThread]
        public static int Main(string[] args)
        {
            try
            {
                Logger.SystemLogger = LogUtils.GetLogger(Console.Error);
                Console.Error.WriteLine("CANAPE.Cli (c) 2017 James Forshaw, 2014 Context Information Security.");
                CommandLineApplication app = new CommandLineApplication(false);

                CommandArgument script = app.Argument("script", "Specify a script file to run.");
                CommandOption compile = app.Option(
                  "-c | --compile", "Compile script file only.",
                  CommandOptionType.NoValue);
                CommandOption verbose = app.Option(
                    "-v | --verbose", "Enable verbose logging output.",
                    CommandOptionType.NoValue);
                CommandOption include = app.Option(
                  "-i | --include", "Specify additional include directories to be accessed via the #load directive.",
                  CommandOptionType.MultipleValue);
                CommandOption libs = app.Option(
                  "-l | --libs", "Specify additional library directories to be accessed via the #r directive.",
                  CommandOptionType.MultipleValue);
                CommandOption color = app.Option(
                    "--color", "Enable ANSI 24 bit color output (if supported).",
                    CommandOptionType.NoValue);
                app.ShowInHelpText = true;
                app.HelpOption("-? | -h | --help");
                app.OnExecute(() =>
                {
                    IEnumerable<string> include_dirs = include.HasValue() ? include.Values.Select(p => Path.GetFullPath(p)) : new string[0];
                    IEnumerable<string> metadata_dirs = libs.HasValue() ? libs.Values.Select(p => Path.GetFullPath(p)) : new string[0];

                    ConsoleUtils.EnableColor = color.HasValue();
                    if (verbose.HasValue())
                    {
                        Logger.SystemLogger.LogLevel = Logger.LogEntryType.All;
                    }
                    if (script.Value == null)
                    {
                        RunConsole(include_dirs, metadata_dirs).Wait();
                    }
                    else
                    {
                        string filename = Path.GetFullPath(script.Value);
                        if (compile.HasValue())
                        {
                            if (CompileScript(filename, include_dirs, metadata_dirs) != null)
                            {
                                Console.Error.WriteLine("SUCCESS: Script compiled with no errors");
                            }
                        }
                        else
                        {
                            RunScript(filename, include_dirs, metadata_dirs, app.RemainingArguments).Wait();
                        }
                    }

                    return 0;
                });
                return app.Execute(args);
            }
            catch (Exception ex)
            {
                PrintException(ex, false);
                return 1;
            }
        }
    }
}
