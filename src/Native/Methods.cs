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
using System.Runtime.InteropServices;

namespace ManagedSandbox.Native
{
    public static class Methods
    {
        /// <summary>
        /// Assigns a process to an existing job object.
        /// </summary>
        /// <param name="hJob">
        /// A handle to the job object to which the process will be associated. The CreateJobObject or OpenJobObject function returns
        /// this handle. The handle must have the JOB_OBJECT_ASSIGN_PROCESS access right.
        /// </param>
        /// <param name="hProcess">
        /// A handle to the process to associate with the job object. The handle must have the PROCESS_SET_QUOTA and PROCESS_TERMINATE
        /// access rights. 
        /// </param>
        /// <returns>
        /// If the function succeeds, the return value is nonzero.
        /// 
        /// If the function fails, the return value is zero. To get extended error information, call GetLastError.
        /// </returns>
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

        /// <summary>
        /// Closes an open object handle.
        /// </summary>
        /// <param name="handle">A valid handle to an open object.</param>
        /// <returns>
        /// If the function succeeds, the return value is nonzero.
        /// 
        /// If the function fails, the return value is zero. To get extended error information, call GetLastError.
        /// </returns>
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr handle);

        /// <summary>
        /// Creates a per-user, per-app profile for Windows Store apps.
        /// </summary>
        /// <param name="pszAppContainerName">
        /// The name of the app container. To ensure uniqueness, it is recommended that this string contains the app name as well
        /// as the publisher. This string can be up to 64 characters in length. Further, it must fit into the pattern described
        /// by the regular expression "[-_. A-Za-z0-9]+".
        /// </param>
        /// <param name="pszDisplayName">
        /// The display name. This string can be up to 512 characters in length.
        /// </param>
        /// <param name="pszDescription">
        /// A description for the app container. This string can be up to 2048 characters in length.
        /// </param>
        /// <param name="pCapabilities">
        /// The SIDs that define the requested capabilities.
        /// </param>
        /// <param name="dwCapabilityCount">
        /// The number of SIDs in pCapabilities.
        /// </param>
        /// <param name="ppSidAppContainerSid">
        /// The SID for the profile.
        /// </param>
        /// <returns>
        /// HResult.OK                  The data store was created successfully.
        /// HResult.AccessDenied        The caller does not have permission to create the profile.
        /// HResult.AlreadyExists       The application data store already exists.
        /// HResult.InvalidParameter    The container name is NULL, or the container name, the display name, or the description
        ///                             strings exceed their specified respective limits for length.
        /// </returns>
        [DllImport("userenv.dll")]
        public static extern UInt32 CreateAppContainerProfile(
            string pszAppContainerName,
            string pszDisplayName,
            string pszDescription,
            [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 4)]
            SID_AND_ATTRIBUTES[] pCapabilities,
            UInt32 dwCapabilityCount,
            out SafeSecurityIdentifier ppSidAppContainerSid);

        /// <summary>
        /// Creates or opens a job object.
        /// </summary>
        /// <param name="lpJobAttributes">
        /// A pointer to a SECURITY_ATTRIBUTES structure that specifies the security descriptor for the job object and determines
        /// whether child processes can inherit the returned handle. If lpJobAttributes is NULL, the job object gets a default security
        /// descriptor and the handle cannot be inherited. The ACLs in the default security descriptor for a job object come from the
        /// primary or impersonation token of the creator.
        /// </param>
        /// <param name="lpName">
        /// The name of the job. The name is limited to MAX_PATH characters. Name comparison is case-sensitive.
        /// 
        /// If lpName is NULL, the job is created without a name.
        /// 
        /// If lpName matches the name of an existing event, semaphore, mutex, waitable timer, or file-mapping object, the function
        /// fails and the GetLastError function returns ERROR_INVALID_HANDLE. This occurs because these objects share the same
        /// namespace.
        /// </param>
        /// <returns>
        /// If the function succeeds, the return value is a handle to the job object. The handle has the JOB_OBJECT_ALL_ACCESS access
        /// right. If the object existed before the function call, the function returns a handle to the existing job object and
        /// GetLastError returns ERROR_ALREADY_EXISTS.
        /// </returns>
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CreateJobObject(
            SECURITY_ATTRIBUTES lpJobAttributes,
            string lpName);

        /// <summary>
        /// Creates a new process and its primary thread. The new process /// runs in the security context of the user represented by
        /// the specified token.
        /// </summary>
        /// <param name="hToken">
        /// A handle to the primary token that represents a user.
        /// </param>
        /// <param name="applicationName">
        /// The name of the module to be executed.
        /// </param>
        /// <param name="commandLine">
        /// The command line to be executed. The maximum length of this string is 32K characters.
        /// </param>
        /// <param name="pProcessAttributes">
        /// A pointer to a SECURITY_ATTRIBUTES structure that specifies a security descriptor for the new process object and determines
        /// whether child processes can inherit the returned handle to the process.
        /// </param>
        /// <param name="pThreadAttributes">
        /// A pointer to a SECURITY_ATTRIBUTES structure that specifies a security descriptor for the new thread object and determines 
        /// whether child processes can inherit the returned handle to the thread.
        /// </param>
        /// <param name="bInheritHandles">
        /// If this parameter is true, each inheritable handle in the calling process is inherited by the new process. If the parameter
        /// is false, the handles are not inherited. 
        /// </param>
        /// <param name="dwCreationFlags">
        /// The flags that control the priority class and the creation of the process.
        /// </param>
        /// <param name="pEnvironment">
        /// A pointer to an environment block for the new process.
        /// </param>
        /// <param name="currentDirectory">
        /// The full path to the current directory for the process.
        /// </param>
        /// <param name="startupInfo">
        /// References a STARTUPINFO structure.
        /// </param>
        /// <param name="processInformation">
        /// Outputs a PROCESS_INFORMATION structure that receives identification information about the new process.
        /// </param>
        /// <returns>
        /// If the function succeeds, the return value is nonzero.
        /// 
        /// If the function fails, the return value is zero. To get extended error information, call GetLastError.
        /// </returns>
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateProcessAsUser(
            SafeTokenHandle hToken,
            string applicationName,
            string commandLine,
            SECURITY_ATTRIBUTES pProcessAttributes,
            SECURITY_ATTRIBUTES pThreadAttributes,
            bool bInheritHandles,
            CREATE_PROCESS_FLAGS dwCreationFlags,
            IntPtr pEnvironment,
            string currentDirectory,
            ref STARTUPINFOEX startupInfo,
            out PROCESS_INFORMATION processInformation);

        /// <summary>
        /// Gets the SID of the specified profile.
        /// </summary>
        /// <param name="appContainerName">
        /// The name of the profile.
        /// </param>
        /// <param name="pSid">
        /// The SID for the profile. 
        /// </param>
        /// <returns>
        /// HResult.OK                  The operation completed successfully.
        /// HResult.InvalidParameter    The appContainerName parameter is either NULL or not valid.
        /// </returns>
        [DllImport("userenv.dll")]
        public static extern UInt32 DeriveAppContainerSidFromAppContainerName(
            string appContainerName,
            out SafeSecurityIdentifier pSid);

        /// <summary>
        /// The FreeSid function frees a security identifier (SID) previously allocated by using the AllocateAndInitializeSid function.
        /// </summary>
        /// <param name="pSid">
        /// A pointer to the SID structure to free.
        /// </param>
        /// <returns>
        /// If the function succeeds, the function returns NULL. If the function fails, it returns a pointer to the SID structure
        /// represented by the pSid parameter.
        /// </returns>
        [DllImport("advapi32.dll")]
        public static extern IntPtr FreeSid(IntPtr pSid);

        /// <summary>
        /// Initializes the specified list of attributes for process and thread creation.
        /// </summary>
        /// <param name="lpAttributeList">
        /// The attribute list. This parameter can be NULL to determine the buffer size required to support the specified number
        /// of attributes.
        /// </param>
        /// <param name="dwAttributeCount">
        /// The count of attributes to be added to the list.
        /// </param>
        /// <param name="dwFlags">
        /// This parameter is reserved and must be zero.
        /// </param>
        /// <param name="lpSize">
        /// If lpAttributeList is not NULL, this parameter specifies the size in bytes of the lpAttributeList buffer on input.
        /// On output, this parameter receives the size in bytes of the initialized attribute list.
        ///
        /// If lpAttributeList is NULL, this parameter receives the required buffer size in bytes.
        /// </param>
        /// <returns>
        /// If the function succeeds, the return value is nonzero.
        ///
        /// If the function fails, the return value is zero.To get extended error information, call Marshal.GetLastWin32Error().
        /// </returns>
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool InitializeProcThreadAttributeList(
             IntPtr lpAttributeList,
             int dwAttributeCount,
             int dwFlags,
             ref Int32 lpSize);

        /// <summary>
        /// Decrements a thread's suspend count. When the suspend count is decremented to zero, the execution of the thread is resumed.
        /// </summary>
        /// <param name="hThread">
        /// A handle to the thread to be restarted.
        /// 
        /// This handle must have the THREAD_SUSPEND_RESUME access right.
        /// </param>
        /// <returns>
        /// If the function succeeds, the return value is the thread's previous suspend count.
        /// 
        /// If the function fails, the return value is (DWORD) -1. To get extended error information, call GetLastError.
        /// </returns>
        [DllImport("kernel32.dll")]
        public static extern uint ResumeThread(IntPtr hThread);

        /// <summary>
        /// Sets limits for a job object.
        /// </summary>
        /// <param name="hJob">
        /// A handle to the job whose limits are being set. The CreateJobObject or OpenJobObject function returns this handle. The
        /// handle must have the JOB_OBJECT_SET_ATTRIBUTES access right.
        /// </param>
        /// <param name="JobObjectInfoClass">
        /// The information class for the limits to be set.
        /// </param>
        /// <param name="lpJobObjectInfo">
        /// The limits or job state to be set for the job. The format of this data depends on the value of JobObjectInfoClass.
        /// </param>
        /// <param name="cbJobObjectInfoLength">
        /// The size of the job information being set, in bytes.
        /// </param>
        /// <returns>
        /// If the function succeeds, the return value is nonzero.
        /// 
        /// If the function fails, the return value is zero. To get extended error information, call GetLastError.
        /// </returns>
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetInformationJobObject(
            IntPtr hJob,
            JOB_OBJECT_INFO_CLASS JobObjectInfoClass,
            IntPtr lpJobObjectInfo,
            Int32 cbJobObjectInfoLength);

        /// <summary>
        /// Updates the specified attribute in a list of attributes for process and thread creation.
        /// </summary>
        /// <param name="lpAttributeList">
        /// A pointer to an attribute list created by the InitializeProcThreadAttributeList function.
        /// </param>
        /// <param name="dwFlags">
        /// This parameter is reserved and must be zero.
        /// </param>
        /// <param name="attribute">
        /// The attribute key to update in the attribute list. This parameter can be one of the following values.
        /// </param>
        /// <param name="lpValue">
        /// TODO: Hint of lifetime
        /// A pointer to the attribute value. This value should persist until the attribute is destroyed using the
        /// DeleteProcThreadAttributeList function.
        /// </param>
        /// <param name="cbSize">
        /// The size of the attribute value specified by the lpValue parameter.
        /// </param>
        /// <param name="lpPreviousValue">
        /// This parameter is reserved and must be IntPtr.Zero.
        /// </param>
        /// <param name="lpReturnSize">
        /// This parameter is reserved and must be IntPtr.Zero.
        /// </param>
        /// <returns>
        /// If the function succeeds, the return value is nonzero.
        ///
        /// If the function fails, the return value is zero.To get extended error information, call Marshal.GetLastWin32Error().
        /// </returns>
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool UpdateProcThreadAttribute(
             IntPtr lpAttributeList,
             uint dwFlags,
             UInt32 attribute,
             IntPtr lpValue,
             Int32 cbSize,
             IntPtr lpPreviousValue,
             IntPtr lpReturnSize);
    }
}
