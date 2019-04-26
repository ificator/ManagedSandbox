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

using ManagedSandbox.Native;

namespace ManagedSandbox.Desktop
{
    public class WindowStation : WindowObject
    {
        private WindowStation(IntPtr handle, bool ownsHandle)
            : base(ownsHandle)
        {
            this.SetHandle(handle);
        }

        /// <summary>
        /// Returns an instance of the window station assigned to the current process.
        /// </summary>
        /// <returns>The current window station</returns>
        public static WindowStation GetCurrent()
        {
            IntPtr unsafeWindowStationHandle = Methods.GetProcessWindowStation();
            if (unsafeWindowStationHandle == IntPtr.Zero)
            {
                throw
                    new SandboxException(
                        "Unable to get current window station",
                        new Win32Exception());
            }

            return new WindowStation(unsafeWindowStationHandle, ownsHandle: false);
        }

        protected override bool ReleaseHandle(IntPtr handleToRelease)
        {
            return Methods.CloseWindowStation(handleToRelease);
        }
    }
}
