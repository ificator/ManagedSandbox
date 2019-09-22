/*
 * MIT License
 * 
 * Copyright (c) 2019 ificator
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

using System;
using System.Diagnostics;
using ManagedSandbox;
using Microsoft.Extensions.DependencyInjection;

namespace ManagedSandboxTest
{
    public class Program
    {
        public static void Main(string[] args)
        {
            try
            {
                var parameters = new Parameters(args);

                if (parameters.InSandbox)
                {
                    Console.WriteLine("In Sandbox! Check process in ProcessExplorer, then press any key to terminate...");
                    Console.ReadKey();
                }
                else
                {
                    Console.WriteLine("In Host! Launching sandbox with args '{0}'", string.Join(" ", args));

                    var services = new ServiceCollection();
                    services.AddManagedSandbox();
                    services.AddConsoleTracer();

                    if (parameters.AppContainer)
                    {
                        services.AddAppContainerProtection("SboxTest");
                    }

                    if (parameters.Desktop)
                    {
                        services.AddDesktopProtection();
                    }

                    if (parameters.JobObject)
                    {
                        services.AddJobObjectProtection();
                    }

                    using (var serviceProvider = services.BuildServiceProvider())
                    {
                        var sandboxedProcess = serviceProvider.GetService<SandboxedProcess>();
                        sandboxedProcess.Start(
                            new ProcessStartInfo
                            {
                                Arguments = "-insandbox",
                                FileName = Environment.GetCommandLineArgs()[0],
                            });
                        sandboxedProcess.Process.WaitForExit();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception: {ex.GetType().Name}");
                Console.WriteLine($"{ex.Message}");
                Console.WriteLine($"{ex.StackTrace}");
            }
        }

        private class Parameters
        {
            public Parameters(string[] args)
            {
                foreach (string arg in args)
                {
                    switch (arg.ToLower())
                    {
                        case "-a":
                        case "-appcontainer":
                            this.AppContainer = true;
                            break;

                        case "-d":
                        case "-desktop":
                            this.Desktop = true;
                            break;

                        case "-insandbox":
                            this.InSandbox = true;
                            break;

                        case "-j":
                        case "-jobobject":
                            this.JobObject = true;
                            break;

                        case "-r":
                        case "-restrictedtoken":
                            this.RestrictedToken = true;
                            break;
                    }
                }
            }

            public bool AppContainer { get; set; }
            public bool Desktop { get; set; }
            public bool InSandbox { get; set; }
            public bool JobObject { get; set; }
            public bool RestrictedToken { get; set; }
        }
    }
}
