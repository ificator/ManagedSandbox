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

namespace ManagedSandbox.Native
{
    public class SafeProcThreadAttributeList : SafeBuffer
    {
        public SafeProcThreadAttributeList(int attributeCount) : base(ownsHandle: true)
        {
            Int32 size = 0;
            Methods.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);

            this.handle = Marshal.AllocHGlobal(size);

            if (!Methods.InitializeProcThreadAttributeList(this.handle, attributeCount, 0, ref size))
            {
                Marshal.FreeHGlobal(this.handle);
                throw new SandboxException(
                    "Unable to initialize process thread attribute list.",
                    new Win32Exception());
            }
        }

        protected override bool ReleaseHandle()
        {
            if (!this.IsInvalid)
            {
                Methods.DeleteProcThreadAttributeList(this.handle);
                Marshal.FreeHGlobal(this.handle);
                this.handle = IntPtr.Zero;
            }

            return true;
        }
    }
}
