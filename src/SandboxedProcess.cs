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
using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;

using ManagedSandbox.Native;

namespace ManagedSandbox
{
    /// <summary>
    /// Launches a process in a sandbox utilizing the provided protections.
    /// </summary>
    public sealed class SandboxedProcess : IDisposable
    {
        private readonly IProtection[] protections = null;
        private readonly ProcessStartInfo startInfo = null;

        private bool disposed = false;
        private Process process = null;

        public SandboxedProcess(ProcessStartInfo startInfo, params IProtection[] protections)
        {
            this.protections = protections ?? new IProtection[0];
            this.startInfo = startInfo ?? throw new ArgumentNullException(nameof(startInfo));

            if (string.IsNullOrEmpty(this.startInfo.FileName))
            {
                throw new ArgumentException(nameof(startInfo.FileName) + " must be specified.");
            }
        }

        ~SandboxedProcess()
        {
            this.Dispose(disposing: false);
        }

        /// <summary>
        /// The <see cref="System.Diagnostics.Process"/> that represents the sandboxed process.
        /// </summary>
        public Process Process
        {
            get
            {
                this.ThrowIfDisposed();
                return this.process;
            }
        }

        /// <summary>
        /// Starts a sandboxed process by specifying the name of a file and the protections to use, and returning a new
        /// <see cref="SandboxedProcess"/>.
        /// </summary>
        /// <param name="fileName">The full path to the file to execute.</param>
        /// <param name="protections">The protections to utilize while creating the process.</param>
        /// <returns>A <see cref="SandboxedProcess"/> instance.</returns>
        public static SandboxedProcess Start(string fileName, params IProtection[] protections)
        {
            return SandboxedProcess.Start(
                new ProcessStartInfo
                {
                    FileName = fileName,
                },
                protections);
        }

        /// <summary>
        /// Starts a sandboxed process by specifying the name of a file, the arguments, and the protections to use, and
        /// returning a new <see cref="SandboxedProcess"/>.
        /// </summary>
        /// <param name="fileName">The full path to the file to execute.</param>
        /// <param name="arguments">The arguments to use when executing the file.</param>
        /// <param name="protections">The protections to utilize while creating the process.</param>
        /// <returns>A <see cref="SandboxedProcess"/> instance.</returns>
        public static SandboxedProcess Start(string fileName, string arguments, params IProtection[] protections)
        {
            return SandboxedProcess.Start(
                new ProcessStartInfo
                {
                    Arguments = arguments,
                    FileName = fileName,
                },
                protections);
        }

        /// <summary>
        /// Starts a sandboxed process by specifying the start info and the protections to use, and returning a new
        /// <see cref="SandboxedProcess"/>.
        /// </summary>
        /// <param name="startInfo">The <see cref="ProcessStartInfo"/> to use to execute.</param>
        /// <param name="protections">The protections to utilize while creating the process.</param>
        /// <returns>A <see cref="SandboxedProcess"/> instance.</returns>
        public static SandboxedProcess Start(ProcessStartInfo startInfo, params IProtection[] protections)
        {
            var sandboxedProcess = new SandboxedProcess(startInfo, protections);
            sandboxedProcess.Start();
            return sandboxedProcess;
        }

        /// <summary>
        /// Starts the sandboxed process.
        /// </summary>
        public void Start()
        {
            using (WindowsIdentity currentIdentity = WindowsIdentity.GetCurrent())
            using (SafeTokenHandle currentToken = new SafeTokenHandle(currentIdentity.Token, ownsHandle: false))
            {
                // Start with the current process' token, and then allow the protections to mutate it as required.
                SafeTokenHandle processToken = currentToken;
                foreach (IProtection protection in this.protections)
                {
                    protection.ModifyToken(ref processToken);
                }

                STARTUPINFOEX startupInfo = new STARTUPINFOEX();
                startupInfo.Init();

                CREATE_PROCESS_FLAGS createProcessFlags = CREATE_PROCESS_FLAGS.NONE;

                // Now allow the protections to change the startup information as required.
                foreach (IProtection protection in this.protections)
                {
                    protection.ModifyStartup(ref startupInfo, ref createProcessFlags);
                }

                string quotedFileName = this.startInfo.FileName;
                if (quotedFileName[0] != '"')
                {
                    quotedFileName = "\"" + quotedFileName + "\"";
                }

                // Start the process.
                PROCESS_INFORMATION processInfo = default;

                try
                {
                    if (!Methods.CreateProcessAsUser(
                            processToken,
                            applicationName: null,
                            commandLine: quotedFileName + " " + this.startInfo.Arguments,
                            pProcessAttributes: null,
                            pThreadAttributes: null,
                            bInheritHandles: false,
                            dwCreationFlags: createProcessFlags,
                            pEnvironment: IntPtr.Zero,
                            currentDirectory: null,
                            ref startupInfo,
                            out processInfo))
                    {
                        throw new SandboxException(
                            "Unable to create process",
                            new Win32Exception());
                    }

                    // Get a managed Process instance so we can avoid reimplementing all its goodness.
                    this.process = Process.GetProcessById(processInfo.dwProcessId);

                    // Let the protections modify the process now that it has been created.
                    foreach (IProtection protection in this.protections)
                    {
                        protection.ModifyProcess(this.process);
                    }

                    // Resume the process.
                    Methods.ResumeThread(processInfo.hThread);
                }
                finally
                {
                    if (processInfo.hProcess != IntPtr.Zero)
                    {
                        Methods.CloseHandle(processInfo.hProcess);
                    }

                    if (processInfo.hThread != IntPtr.Zero)
                    {
                        Methods.CloseHandle(processInfo.hThread);
                    }
                }
            }
        }

        public void Dispose()
        {
            this.Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool disposing)
        {
            this.ThrowIfDisposed();

            try
            {
                if (disposing)
                {
                    if (this.process != null)
                    {
                        if (!this.process.HasExited)
                        {
                            try
                            {
                                // We'll attempt to terminate the process here, but realistically the releasing of the
                                // job objects handle will result in termination anyway so we won't bother with error
                                // scenarios.
                                this.process.Kill();
                                this.process.WaitForExit(1000 /* milliseconds */);
                            }
                            catch
                            {
                            }
                        }

                        this.process.Close();
                    }
                }

                // The protections likely hold handles to native resources, so we always need to dispose them to avoid
                // potential leaks.
                foreach (IProtection protection in this.protections)
                {
                    protection.Dispose();
                }
            }
            finally
            {
                this.disposed = true;
            }
        }

        private void ThrowIfDisposed()
        {
            if (this.disposed)
            {
                throw new ObjectDisposedException(nameof(SandboxedProcess));
            }
        }
    }
}
