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
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using ManagedSandbox.Native;
using ManagedSandbox.Tracing;

namespace ManagedSandbox.Desktop
{
    public class Desktop : WindowObject
    {
        private Desktop(IntPtr handle, bool ownsHandle)
            : base(ownsHandle)
        {
            this.SetHandle(handle);
        }

        /// <summary>
        /// Creates a new desktop with minimal rights.
        /// </summary>
        /// <param name="tracer">A tracer instance.</param>
        /// <returns>The desktop instance.</returns>
        public static Desktop Create(ITracer tracer, string mandatoryLevelSacl)
        {
            using (var disposalEscrow = new DisposalEscrow())
            using (Desktop currentDesktop = Desktop.GetCurrent())
            {
                try
                {
                    string name = "sbox" + DateTime.UtcNow.Ticks;
                    tracer.Trace(nameof(Desktop), "Creating desktop '{0}'", name);

                    SECURITY_ATTRIBUTES securityAttributes = null;
                    if (mandatoryLevelSacl != null)
                    {
                        tracer.Trace(nameof(Desktop), "Generating security attributes for '{0}'", mandatoryLevelSacl);

                        // If a security descriptor (in SDDL form) was provided convert it to binary form and then marshal
                        // it into native memory to that we can pass it in to the native method.
                        var rawSecurityDescriptor = new RawSecurityDescriptor(mandatoryLevelSacl);

                        var binaryForm = new byte[rawSecurityDescriptor.BinaryLength];
                        rawSecurityDescriptor.GetBinaryForm(binaryForm, 0 /* offset */);

                        var nativeBinaryForm = disposalEscrow.Add(new SafeHGlobalBuffer(binaryForm.Length));
                        Marshal.Copy(binaryForm, 0 /* startIndex */, nativeBinaryForm.DangerousGetHandle(), binaryForm.Length);

                        securityAttributes = new SECURITY_ATTRIBUTES { lpSecurityDescriptor = nativeBinaryForm.DangerousGetHandle() };
                    }

                    // Since we're creating the desktop we'll ask for all rights so that we have the ability to modify security as
                    // required. Since the created desktop will be referenced by name when creating the process this will not impact
                    // the security of the desktop.
                    IntPtr unsafeDesktopHandle = Methods.CreateDesktop(
                        name,
                        device: null,
                        deviceMode: null,
                        flags: 0,
                        accessMask: DESKTOP_RIGHTS.GENERIC_ALL,
                        attributes: securityAttributes);
                    if (unsafeDesktopHandle == IntPtr.Zero)
                    {
                        throw
                            new SandboxException(
                                $"Unable to create new desktop",
                                new Win32Exception());
                    }

                    tracer.Trace(nameof(Desktop), "Desktop successfully created");

                    return new Desktop(unsafeDesktopHandle, ownsHandle: true)
                    {
                        Name = name,
                    };
                }
                finally
                {
                    // Since CreateDesktop automatically switches to the new desktop we need to make sure that we switch back
                    // to the original one.
                    currentDesktop.MakeCurrent();
                }
            }
        }

        /// <summary>
        /// Returns an instance of the desktop assigned to the current thread.
        /// </summary>
        /// <returns>The current desktop</returns>

        public static Desktop GetCurrent()
        {
            IntPtr unsafeDesktopHandle = Methods.GetThreadDesktop(Methods.GetCurrentThreadId());
            if (unsafeDesktopHandle == IntPtr.Zero)
            {
                throw
                    new SandboxException(
                        "Unabled to get current desktop",
                        new Win32Exception());
            }

            // The current process owns the handle returned by GetThreadDesktop, so we need to make sure that we 
            // do not close it when the Desktop instance is disposed.
            return new Desktop(unsafeDesktopHandle, ownsHandle: false);
        }

        /// <summary>
        /// Assigns this Desktop instance to the current thread.
        /// </summary>
        public void MakeCurrent()
        {
            Methods.SetThreadDesktop(this.handle);
        }

        protected override bool ReleaseHandle(IntPtr handleToRelease)
        {
            return Methods.CloseDesktop(handleToRelease);
        }
    }
}
