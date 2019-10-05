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
using System.Runtime.InteropServices;
using ManagedSandbox.Native;
using ManagedSandbox.Tracing;
using Microsoft.Win32.SafeHandles;

namespace ManagedSandbox.JobObject
{
    public class JobObject : SafeHandleZeroOrMinusOneIsInvalid
    {
        private readonly ITracer tracer;

        private JobObject(ITracer tracer, IntPtr unsafeJobObjectHandle, bool ownsHandle)
            : base(ownsHandle)
        {
            this.tracer = tracer;
            this.SetHandle(unsafeJobObjectHandle);
        }

        /// <summary>
        /// Creates a job object with the provided name, or opens one if it already exists.
        /// </summary>
        /// <param name="tracer">A tracer instance.</param>
        /// <param name="jobObjectName">The name of the job object, or null if it should be unnamed</param>
        /// <returns>The handle to the new (or reused) job object</returns>
        public static JobObject CreateOrOpenJobObject(ITracer tracer, string jobObjectName)
        {
            tracer.Trace(nameof(JobObject), "Creating job object '{0}'", jobObjectName);
            IntPtr unsafeJobObjectHandle = Methods.CreateJobObject(null /* lpJobAttributes */, jobObjectName);
            if (unsafeJobObjectHandle == IntPtr.Zero)
            {
                throw
                    new SandboxException(
                        $"Unable to create or open job object '{jobObjectName}'",
                        new Win32Exception());
            }

            var jobObject = new JobObject(tracer, unsafeJobObjectHandle, true /* ownsHandle */);

            try
            {
                jobObject.SetLimits();
                jobObject.SetUiRestrictions();
            }
            catch
            {
                jobObject.Dispose();
                throw;
            }

            return jobObject;
        }

        /// <summary>
        /// Assigns the specified process to the current job object.
        /// </summary>
        /// <param name="process">The process to assign to the job object.</param>
        public void AssignProcess(Process process)
        {
            this.tracer.Trace(nameof(JobObject), "Assigning process {0}", process.Id);
            if (!Methods.AssignProcessToJobObject(this.handle, process.Handle))
            {
                throw
                    new SandboxException(
                        "Unable to assign process to job object",
                        new Win32Exception());
            }
        }

        /// <summary>
        /// Sets limits.
        /// </summary>
        /// <param name="activeProcessLimit">The number of processes that can be added to the job object.</param>
        /// <param name="jobMemoryLimitInBytes">The total amount of memory that can be consumed by all processes in the job object.</param>
        /// <param name="limitFlags">The limits that are in effect.</param>
        /// <param name="processMemoryLimitInBytes">The maximum number of bytes a process can consume.</param>
        public void SetLimits(
            uint? activeProcessLimit = null,
            ulong? jobMemoryLimitInBytes = null,
            JOB_OBJECT_LIMIT_FLAGS limitFlags = JOB_OBJECT_LIMIT_FLAGS.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            ulong? processMemoryLimitInBytes = null)
        {
            this.tracer.Trace(nameof(JobObject), "Setting limits");

            var extendedLimitInformation = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION
            {
                BasicLimitInformation =
                {
                    LimitFlags = limitFlags,
                },
            };

            if (activeProcessLimit.HasValue)
            {
                extendedLimitInformation.BasicLimitInformation.ActiveProcessLimit = activeProcessLimit.GetValueOrDefault();
                extendedLimitInformation.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_FLAGS.JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            }

            if (jobMemoryLimitInBytes.HasValue)
            {
                extendedLimitInformation.JobMemoryLimit = new UIntPtr(jobMemoryLimitInBytes.GetValueOrDefault());
                extendedLimitInformation.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_FLAGS.JOB_OBJECT_LIMIT_JOB_MEMORY;
            }

            if (processMemoryLimitInBytes.HasValue)
            {
                extendedLimitInformation.ProcessMemoryLimit = new UIntPtr(processMemoryLimitInBytes.GetValueOrDefault());
                extendedLimitInformation.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_FLAGS.JOB_OBJECT_LIMIT_PROCESS_MEMORY;
            }

            // Apply the limits to the job object.
            using (var nativeExtendedLimitInformation = new SafeHGlobalBuffer(Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION))))
            {
                Marshal.StructureToPtr(extendedLimitInformation, nativeExtendedLimitInformation.DangerousGetHandle(), fDeleteOld: false);

                if (!Methods.SetInformationJobObject(
                        this.handle,
                        JOB_OBJECT_INFO_CLASS.JobObjectExtendedLimitInformation,
                        nativeExtendedLimitInformation.DangerousGetHandle(),
                        nativeExtendedLimitInformation.Size))
                {
                    throw
                        new SandboxException(
                            "Unable to set job object limit information",
                            new Win32Exception());
                }
            }
        }

        /// <summary>
        /// Sets UI restrictions.
        /// </summary>
        /// <param name="uiRestrictionsClass">The restriction class for the UI.</param>
        public void SetUiRestrictions(JOB_OBJECT_UILIMIT_FLAGS uiRestrictionsClass = JOB_OBJECT_UILIMIT_FLAGS.ALL)
        {
            this.tracer.Trace(nameof(JobObject), "Setting UI restrictions");

            var uiRestrictions = new JOBOBJECT_BASIC_UI_RESTRICTIONS
            {
                UIRestrictionsClass = uiRestrictionsClass,
            };

            using (var nativeUiRestrictions = new SafeHGlobalBuffer(Marshal.SizeOf(typeof(JOBOBJECT_BASIC_UI_RESTRICTIONS))))
            {
                Marshal.StructureToPtr(
                    uiRestrictions,
                    nativeUiRestrictions.DangerousGetHandle(),
                    false /* fDeleteOld */);

                if (!Methods.SetInformationJobObject(
                    this.handle,
                    JOB_OBJECT_INFO_CLASS.JobObjectBasicUIRestrictions,
                    nativeUiRestrictions.DangerousGetHandle(),
                    nativeUiRestrictions.Size))
                {
                    throw
                        new SandboxException(
                            "Unable to set job object basic ui restrictions",
                            new Win32Exception());
                }
            }
        }

        protected override bool ReleaseHandle()
        {
            if (this.IsInvalid)
            {
                return false;
            }

            bool handleClosed = Methods.CloseHandle(this.handle);
            if (handleClosed)
            {
                this.SetHandleAsInvalid();
            }

            return handleClosed;
        }
    }
}
