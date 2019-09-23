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

using System.Diagnostics;
using ManagedSandbox.Native;
using ManagedSandbox.Tracing;

namespace ManagedSandbox.JobObject
{
    public class JobObjectProtection : IProtection
    {
        public JobObjectProtection(ITracer tracer)
        {
            this.JobObject = JobObject.CreateOrOpenJobObject(tracer, jobObjectName: null);
        }

        /// <summary>
        /// The <see cref="JobObject"/> instance utilized for this protection.
        /// </summary>
        public JobObject JobObject { get; }

        public void Dispose()
        {
            this.JobObject.Dispose();
        }

        public void ModifyProcess(Process process)
        {
            this.JobObject.AssignProcess(process);
        }

        public void ModifyStartup(ref STARTUPINFOEX startupInfoEx, ref CREATE_PROCESS_FLAGS createProcessFlags)
        {
        }

        public void ModifyToken(ref SafeTokenHandle currentToken)
        {
        }
    }
}
