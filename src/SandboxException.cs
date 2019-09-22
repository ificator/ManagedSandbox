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

namespace ManagedSandbox
{
    public class SandboxException : Exception
    {
        public SandboxException(string message, HResult hresult) : base(message)
        {
            this.HResult = hresult;
        }

        public SandboxException(string message, Win32Exception innerException) : base(message, innerException)
        {
            this.HResult = SandboxException.MapErrorToHResult((Error)innerException.NativeErrorCode);
        }

        public new HResult HResult
        {
            get { return (HResult)base.HResult; }
            set { base.HResult = (int)value; }
        }

        private static HResult MapErrorToHResult(Error error)
        {
            switch (error)
            {
                case Error.AccessDenied:        return Native.HResult.AccessDenied;
                case Error.AlreadyExists:       return Native.HResult.AlreadyExists;
                case Error.InsufficientBuffer:  return Native.HResult.InsufficientBuffer;
                case Error.InvalidParameter:    return Native.HResult.InvalidParameter;
                default:                        return Native.HResult.Unknown;
            }
        }
    }
}
