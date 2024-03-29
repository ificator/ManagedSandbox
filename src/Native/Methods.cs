﻿/*
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
        /// The AllocateAndInitializeSid function allocates and initializes a 
        /// security identifier (SID) with up to eight subauthorities.
        /// </summary>
        /// <param name="pIdentifierAuthority">
        /// A reference of a SID_IDENTIFIER_AUTHORITY structure. This 
        /// structure provides the top-level identifier authority value to 
        /// set in the SID.
        /// </param>
        /// <param name="nSubAuthorityCount">
        /// Specifies the number of subauthorities to place in the SID. 
        /// </param>
        /// <param name="dwSubAuthority0">
        /// Subauthority value to place in the SID.
        /// </param>
        /// <param name="dwSubAuthority1">
        /// Subauthority value to place in the SID.
        /// </param>
        /// <param name="dwSubAuthority2">
        /// Subauthority value to place in the SID.
        /// </param>
        /// <param name="dwSubAuthority3">
        /// Subauthority value to place in the SID.
        /// </param>
        /// <param name="dwSubAuthority4">
        /// Subauthority value to place in the SID.
        /// </param>
        /// <param name="dwSubAuthority5">
        /// Subauthority value to place in the SID.
        /// </param>
        /// <param name="dwSubAuthority6">
        /// Subauthority value to place in the SID.
        /// </param>
        /// <param name="dwSubAuthority7">
        /// Subauthority value to place in the SID.
        /// </param>
        /// <param name="pSid">
        /// Outputs the allocated and initialized SID structure.
        /// </param>
        /// <returns>
        /// If the function succeeds, the return value is true.
        /// 
        /// If the function fails, the return value is false. To get extended error information, call GetLastError.
        /// </returns>
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool AllocateAndInitializeSid(
            ref SID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
            byte nSubAuthorityCount,
            int dwSubAuthority0,
            int dwSubAuthority1,
            int dwSubAuthority2,
            int dwSubAuthority3,
            int dwSubAuthority4,
            int dwSubAuthority5,
            int dwSubAuthority6,
            int dwSubAuthority7,
            out SafeSecurityIdentifier pSid);

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
        /// Closes an open handle to a desktop object.
        /// </summary>
        /// <param name="handle">
        /// A handle to the desktop to be closed. This can be a handle returned by the CreateDesktop, OpenDesktop, or OpenInputDesktop
        /// functions. Do not specify the handle returned by the GetThreadDesktop function.
        /// </param>
        /// <returns>
        /// If the function succeeds, the return value is nonzero.
        /// 
        /// If the function fails, the return value is zero. To get extended error information, call GetLastError.
        /// </returns>
        [DllImport("user32.dll", EntryPoint = "CloseDesktop", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseDesktop(IntPtr handle);

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
        /// Closes an open window station handle.
        /// </summary>
        /// <param name="hWinsta">
        /// A handle to the window station to be closed. This handle is returned by the CreateWindowStation or OpenWindowStation
        /// function. Do not specify the handle returned by the GetProcessWindowStation function.
        /// </param>
        /// <returns>
        /// If the function succeeds, the return value is nonzero.
        /// 
        /// If the function fails, the return value is zero. To get extended error information, call GetLastError.
        /// </returns>
        [DllImport("user32", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseWindowStation(IntPtr hWinsta);

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
        public static extern HResult CreateAppContainerProfile(
            string pszAppContainerName,
            string pszDisplayName,
            string pszDescription,
            [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 4)]
            SID_AND_ATTRIBUTES[] pCapabilities,
            UInt32 dwCapabilityCount,
            out SafeSecurityIdentifier ppSidAppContainerSid);

        /// <summary>
        /// Creates a new desktop, associates it with the current window station of the calling process, and assigns it to the calling
        /// thread. The calling process must have an associated window station, either assigned by the system at process creation time
        /// or set by the SetProcessWindowStation function.
        /// </summary>
        /// <param name="desktopName">
        /// The name of the desktop to be created. Desktop names are case-insensitive and may not contain backslash characters (\).
        /// </param>
        /// <param name="device">
        /// Reserved; must be NULL.
        /// </param>
        /// <param name="deviceMode">
        /// Reserved; must be NULL.
        /// </param>
        /// <param name="flags">
        /// Must be 0.
        /// </param>
        /// <param name="accessMask">
        /// The access to the desktop. For a list of values, see Desktop Security and Access Rights.
        /// </param>
        /// <param name="attributes">
        /// A pointer to a SECURITY_ATTRIBUTES structure that determines whether the returned handle can be inherited by child
        /// processes. If lpsa is NULL, the handle cannot be inherited.
        /// </param>
        /// <returns>
        /// If the function succeeds, the return value is a handle to the newly created desktop. If the specified desktop already
        /// exists, the function succeeds and returns a handle to the existing desktop. When you are finished using the handle, call
        /// the CloseDesktop function to close it.
        /// </returns>
        [DllImport("user32.dll", EntryPoint = "CreateDesktop", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CreateDesktop(
            [MarshalAs(UnmanagedType.LPWStr)] string desktopName,
            [MarshalAs(UnmanagedType.LPWStr)] string device,
            [MarshalAs(UnmanagedType.LPWStr)] string deviceMode,
            [MarshalAs(UnmanagedType.U4)] int flags,
            [MarshalAs(UnmanagedType.U4)] DESKTOP_RIGHTS accessMask,
            [MarshalAs(UnmanagedType.LPStruct)] SECURITY_ATTRIBUTES attributes);

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
        /// The CreateRestrictedToken function creates a new access token that is a restricted version of an existing access token. The
        /// restricted token can have disabled security identifiers (SIDs), deleted privileges, and a list of restricting SIDs. For
        /// more information, see Restricted Tokens.
        /// </summary>
        /// <param name="hExistingToken">
        /// A handle to a primary or impersonation token. The token can also be a restricted token. The handle must have
        /// TOKEN_DUPLICATE access to the token.
        /// </param>
        /// <param name="flags">
        /// Specifies additional privilege options.
        /// </param>
        /// <param name="disableSidCount">
        /// Specifies the number of entries in the SidsToDisable array.
        /// </param>
        /// <param name="sidsToDisable">
        /// A pointer to an array of SID_AND_ATTRIBUTES structures that specify the deny-only SIDs in the restricted token. The system
        /// uses a deny-only SID to deny access to a securable object. The absence of a deny-only SID does not allow access.
        /// </param>
        /// <param name="deletePrivilegeCount">
        /// Specifies the number of entries in the PrivilegesToDelete array.
        /// </param>
        /// <param name="privilegesToDelete">
        /// A pointer to an array of LUID_AND_ATTRIBUTES structures that specify the privileges to delete in the restricted token.
        /// </param>
        /// <param name="restrictedSidCount">
        /// Specifies the number of entries in the SidsToRestrict array.
        /// </param>
        /// <param name="sidsToRestrict">
        /// A pointer to an array of SID_AND_ATTRIBUTES structures that specify a list of restricting SIDs for the new token. If the
        /// existing token is a restricted token, the list of restricting SIDs for the new token is the intersection of this array and
        /// the list of restricting SIDs for the existing token. No check is performed to remove duplicate SIDs that were placed on the
        /// SidsToRestrict parameter. Duplicate SIDs allow a restricted token to have redundant information in the restricting SID
        /// list.
        /// </param>
        /// <param name="hNewToken">
        /// A pointer to a variable that receives a handle to the new restricted token. This handle has the same access rights as
        /// ExistingTokenHandle. The new token is the same type, primary or impersonation, as the existing token. The handle returned
        /// in NewTokenHandle can be duplicated.
        /// </param>
        /// <returns>
        /// If the function succeeds, the return value is nonzero.
        /// 
        /// If the function fails, the return value is zero. To get extended error information, call GetLastError.
        /// </returns>
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateRestrictedToken(
            SafeTokenHandle hExistingToken,
            RESTRICTED_TOKEN_FLAGS flags,
            UInt32 disableSidCount,
            [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2)]
            SID_AND_ATTRIBUTES[] sidsToDisable,
            UInt32 deletePrivilegeCount,
            [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 4)]
            LUID_AND_ATTRIBUTES[] privilegesToDelete,
            UInt32 restrictedSidCount,
            [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 6)]
            SID_AND_ATTRIBUTES[] sidsToRestrict,
            out SafeTokenHandle hNewToken);

        /// <summary>
        /// Creates a SID for predefined aliases.
        /// </summary>
        /// <param name="wellKnownSidType">
        /// Member of the WELL_KNOWN_SID_TYPE enumeration that specifies what the SID will identify.
        /// </param>
        /// <param name="domainSid">
        /// A pointer to a SID that identifies the domain to use when creating the SID. Pass NULL to use the local computer.
        /// </param>
        /// <param name="pSid">
        /// A pointer to memory where CreateWellKnownSid will store the new SID.
        /// </param>
        /// <param name="cbSid">
        /// A pointer to a DWORD that contains the number of bytes available at pSid. The CreateWellKnownSid function stores
        /// the number of bytes actually used at this location.
        /// </param>
        /// <returns></returns>
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateWellKnownSid(
            WELL_KNOWN_SID_TYPE wellKnownSidType,
            IntPtr domainSid,
            SafeHGlobalBuffer pSid,
            ref Int32 cbSid);

        /// <summary>
        /// Deletes the specified per-user, per-app profile.
        /// </summary>
        /// <param name="pszAppContainerName">
        /// he name given to the profile in the call to the CreateAppContainerProfile function. This string is at most 64 characters
        /// in length, and fits into the pattern described by the regular expression "[-_. A-Za-z0-9]+".
        /// </param>
        /// <returns>
        /// HResult.OK                  The profile was deleted successfully.
        /// HResult.InvalidParameter    The pszAppContainerName parameter is either NULL or not valid.
        /// </returns>
        [DllImport("userenv.dll")]
        public static extern HResult DeleteAppContainerProfile(string pszAppContainerName);

        /// <summary>
        /// Deletes the specified list of attributes for process and thread creation.
        /// </summary>
        /// <param name="lpAttributeList">
        /// The attribute list. This list is created by the InitializeProcThreadAttributeList function.
        /// </param>
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern void DeleteProcThreadAttributeList(IntPtr lpAttributeList);

        /// <summary>
        /// Gets the path of the local app data folder for the specified app container.
        /// </summary>
        /// <param name="pszAppContainerSid">The SID of the app container (in string form).</param>
        /// <param name="ppszPath">The path of the local folder.</param>
        /// <returns>
        /// HResult.OK                  The profile was deleted successfully.
        /// HResult.InvalidParameter    The pszAppContainerName parameter is either NULL or not valid.
        /// </returns>
        [DllImport("userenv.dll")]
        public static extern HResult GetAppContainerFolderPath(string pszAppContainerSid, out string ppszPath);

        /// <summary>
        /// Retrieves a handle to the current window station for the calling process.
        /// </summary>
        /// <returns>
        /// If the function succeeds, the return value is a handle to the window station.
        /// </returns>
        [DllImport("user32", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr GetProcessWindowStation();

        /// <summary>
        /// Retrieves information about the specified window station or desktop object.
        /// </summary>
        /// <param name="hObj">
        /// A handle to the window station or desktop object. This handle is returned by the CreateWindowStation, OpenWindowStation,
        /// CreateDesktop, or OpenDesktop function.
        /// </param>
        /// <param name="nIndex">
        /// The information to be retrieved.
        /// </param>
        /// <param name="pvInfo">
        /// A pointer to a buffer to receive the object information.
        /// </param>
        /// <param name="nLength">
        /// The size of the buffer pointed to by the pvInfo parameter, in bytes.
        /// </param>
        /// <param name="lpnLengthNeeded">
        /// A pointer to a variable receiving the number of bytes required to store the requested information. If this variable's value
        /// is greater than the value of the nLength parameter when the function returns, the function returns FALSE, and none of the
        /// information is copied to the pvInfo buffer. If the value of the variable pointed to by lpnLengthNeeded is less than or
        /// equal to the value of nLength, the entire information block is copied.
        /// </param>
        /// <returns>
        /// If the function succeeds, the return value is nonzero.
        /// 
        /// If the function fails, the return value is zero. To get extended error information, call GetLastError.
        /// </returns>
        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool GetUserObjectInformation(
            IntPtr hObj,
            int nIndex,
            IntPtr pvInfo,
            uint nLength,
            out uint lpnLengthNeeded);

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
        public static extern HResult DeriveAppContainerSidFromAppContainerName(
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
        /// Retrieves the thread identifier of the calling thread.
        /// </summary>
        /// <returns>
        /// The return value is the thread identifier of the calling thread.
        /// </returns>
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int GetCurrentThreadId();

        /// <summary>
        /// The function returns the length, in bytes, of a valid security 
        /// identifier (SID).
        /// </summary>
        /// <param name="pSID">
        /// A pointer to the SID structure whose length is returned. 
        /// </param>
        /// <returns>
        /// If the SID structure is valid, the return value is the length, in 
        /// bytes, of the SID structure.
        /// </returns>
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int GetLengthSid(IntPtr pSID);

        /// <summary>
        /// The function retrieves a specified type of information about an access token. The calling process must have appropriate
        /// access rights to obtain the information.
        /// </summary>
        /// <param name="hToken">
        /// A handle to an access token from which information is retrieved.
        /// </param>
        /// <param name="tokenInfoClass">
        /// Specifies a value from the TOKEN_INFORMATION_CLASS enumerated type to identify the type of information the function
        /// retrieves.
        /// </param>
        /// <param name="pTokenInfo">
        /// A pointer to a buffer the function fills with the requested information.
        /// </param>
        /// <param name="tokenInfoLength">
        /// Specifies the size, in bytes, of the buffer pointed to by the TokenInformation parameter.
        /// </param>
        /// <param name="returnLength">
        /// A pointer to a variable that receives the number of bytes needed for the buffer pointed to by the TokenInformation
        /// parameter.
        /// </param>
        /// <returns>
        /// If the function succeeds, the return value is nonzero.
        /// 
        /// If the function fails, the return value is zero. To get extended error information, call GetLastError.
        /// </returns>
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetTokenInformation(
            SafeTokenHandle hToken,
            TOKEN_INFORMATION_CLASS tokenInfoClass,
            IntPtr pTokenInfo,
            Int32 tokenInfoLength,
            out Int32 returnLength);

        /// <summary>
        /// Retrieves a handle to the desktop assigned to the specified thread.
        /// </summary>
        /// <param name="dwThreadId">
        /// The thread identifier. The GetCurrentThreadId and CreateProcess functions return thread identifiers.
        /// </param>
        /// <returns>
        /// If the function succeeds, the return value is a handle to the desktop associated with the specified thread. You do not need
        /// to call the CloseDesktop function to close the returned handle.
        /// </returns>
        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetThreadDesktop(int dwThreadId);

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
        /// Assigns the specified desktop to the calling thread. All subsequent operations on the desktop use the access rights granted
        /// to the desktop.
        /// </summary>
        /// <param name="hDesktop">
        /// A handle to the desktop to be assigned to the calling thread. This handle is returned by the CreateDesktop,
        /// GetThreadDesktop, OpenDesktop, or OpenInputDesktop function.
        /// </param>
        /// <returns>
        /// If the function succeeds, the return value is the thread's previous suspend count.
        /// 
        /// If the function fails, the return value is (DWORD) -1. To get extended error information, call GetLastError.
        /// </returns>
        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool SetThreadDesktop(IntPtr hDesktop);

        /// <summary>
        /// The function sets various types of information for a specified access token. The information that this function sets
        /// replaces existing information. The calling process must have appropriate access rights to set the information.
        /// </summary>
        /// <param name="hToken">
        /// A handle to the access token for which information is to be set.
        /// </param>
        /// <param name="tokenInfoClass">
        /// A value from the TOKEN_INFORMATION_CLASS enumerated type that identifies the type of information the function sets.
        /// </param>
        /// <param name="pTokenInfo">
        /// A pointer to a buffer that contains the information set in the access token.
        /// </param>
        /// <param name="tokenInfoLength">
        /// Specifies the length, in bytes, of the buffer pointed to by TokenInformation.
        /// </param>
        /// <returns>
        /// If the function succeeds, the return value is the thread's previous suspend count.
        /// 
        /// If the function fails, the return value is (DWORD) -1. To get extended error information, call GetLastError.
        /// </returns>
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetTokenInformation(
            SafeTokenHandle hToken,
            TOKEN_INFORMATION_CLASS tokenInfoClass,
            IntPtr pTokenInfo,
            Int32 tokenInfoLength);

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
             PROC_THREAD_ATTRIBUTES attribute,
             IntPtr lpValue,
             Int32 cbSize,
             IntPtr lpPreviousValue,
             IntPtr lpReturnSize);
    }
}
