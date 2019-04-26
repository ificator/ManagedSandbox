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

using ManagedSandbox.Native;
using Microsoft.Win32.SafeHandles;

namespace ManagedSandbox.Desktop
{
    public abstract class WindowObject : SafeHandleZeroOrMinusOneIsInvalid
    {
        private string name;

        protected WindowObject(bool ownsHandle)
            : base(ownsHandle)
        {
        }

        /// <summary>
        /// The name associated with the window object.
        /// </summary>
        public string Name
        {
            get
            {
                if (string.IsNullOrWhiteSpace(this.name))
                {
                    uint lpnLengthNeeded;
                    Methods.GetUserObjectInformation(
                        this.handle,
                        2 /* UOI_NAME */,
                        IntPtr.Zero,
                        0 /* nLength */,
                        out lpnLengthNeeded);
                    if (lpnLengthNeeded <= 0)
                    {
                        throw
                            new SandboxException(
                                "Unable to determine length of object information",
                                new Win32Exception());
                    }

                    using (var memoryBuffer = new SafeHGlobalBuffer((int)lpnLengthNeeded))
                    {
                        Methods.GetUserObjectInformation(
                            this.handle,
                            2 /* UOI_NAME */,
                            memoryBuffer.DangerousGetHandle(),
                            lpnLengthNeeded,
                            out lpnLengthNeeded);
                        if (lpnLengthNeeded <= 0)
                        {
                            throw
                                new SandboxException(
                                    "Unable to get object information",
                                    new Win32Exception());
                        }

                        this.name = Marshal.PtrToStringAnsi(memoryBuffer.DangerousGetHandle());
                    }
                }

                return this.name;
            }

            protected set
            {
                this.name = value;
            }
        }

        protected override bool ReleaseHandle()
        {
            if (this.IsInvalid)
            {
                return false;
            }

            bool handleClosed = this.ReleaseHandle(this.handle);
            if (handleClosed)
            {
                this.SetHandleAsInvalid();
            }

            return handleClosed;
        }

        protected abstract bool ReleaseHandle(IntPtr handleToRelease);
    }
}
