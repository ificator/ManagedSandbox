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

namespace ManagedSandbox.Native
{
    /// <summary>
    /// The following process creation flags are used by the CreateProcess, CreateProcessAsUser, CreateProcessWithLogonW, and
    /// CreateProcessWithTokenW functions. They can be specified in any combination, except as noted.
    /// </summary>
    [Flags]
    public enum CREATE_PROCESS_FLAGS
    {
        NONE                                = 0x00000000,

        /// <summary>
        /// The calling thread starts and debugs the new process and all child processes created by the new process. It can receive
        /// all related debug events using the WaitForDebugEvent function. 
        /// A process that uses DEBUG_PROCESS becomes the root of a debugging chain. This continues until another process in the
        /// chain is created with DEBUG_PROCESS.
        /// If this flag is combined with DEBUG_ONLY_THIS_PROCESS, the caller debugs only the new process, not any child processes.
        /// </summary>
        DEBUG_PROCESS                       = 0x00000001,

        /// <summary>
        /// The calling thread starts and debugs the new process. It can receive all related debug events using the WaitForDebugEvent
        /// function.
        /// </summary>
        DEBUG_ONLY_THIS_PROCESS             = 0x00000002,

        /// <summary>
        /// The primary thread of the new process is created in a suspended state, and does not run until the ResumeThread function
        /// is called.
        /// </summary>
        CREATE_SUSPENDED                    = 0x00000004,

        /// <summary>
        /// For console processes, the new process does not inherit its parent's console (the default). The new process can call the
        /// AllocConsole function at a later time to create a console.
        /// This value cannot be used with CREATE_NEW_CONSOLE.
        /// </summary>
        DETACHED_PROCESS                    = 0x00000008,

        /// <summary>
        /// The new process has a new console, instead of inheriting its parent's console (the default).
        /// This flag cannot be used with DETACHED_PROCESS.
        /// </summary>
        CREATE_NEW_CONSOLE                  = 0x00000010,

        /// <summary>
        /// The new process is the root process of a new process group. The process group includes all processes that are descendants
        /// of this root process. The process identifier of the new process group is the same as the process identifier, which is
        /// returned in the lpProcessInformation parameter. Process groups are used by the GenerateConsoleCtrlEvent function to
        /// enable sending a CTRL+BREAK signal to a group of console processes.
        /// If this flag is specified, CTRL+C signals will be disabled for all processes within the new process group.
        /// This flag is ignored if specified with CREATE_NEW_CONSOLE.
        /// </summary>
        CREATE_NEW_PROCESS_GROUP            = 0x00000200,

        /// <summary>
        /// If this flag is set, the environment block pointed to by lpEnvironment uses Unicode characters. Otherwise, the environment
        /// block uses ANSI characters.
        /// </summary>
        CREATE_UNICODE_ENVIRONMENT          = 0x00000400,

        /// <summary>
        /// This flag is valid only when starting a 16-bit Windows-based application. If set, the new process runs in a private Virtual
        /// DOS Machine (VDM). By default, all 16-bit Windows-based applications run as threads in a single, shared VDM. The advantage
        /// of running separately is that a crash only terminates the single VDM; any other programs running in distinct VDMs continue
        /// to function normally. Also, 16-bit Windows-based applications that are run in separate VDMs have separate input queues. That
        /// means that if one application stops responding momentarily, applications in separate VDMs continue to receive input. The
        /// disadvantage of running separately is that it takes significantly more memory to do so. You should use this flag only if
        /// the user requests that 16-bit applications should run in their own VDM.
        /// </summary>
        CREATE_SEPARATE_WOW_VDM = 0x00000800,

        /// <summary>
        /// The flag is valid only when starting a 16-bit Windows-based application. If the DefaultSeparateVDM switch in the Windows
        /// section of WIN.INI is TRUE, this flag overrides the switch. The new process is run in the shared Virtual DOS Machine.
        /// </summary>
        CREATE_SHARED_WOW_VDM               = 0x00001000,

        /// <summary>
        /// The process inherits its parent's affinity. If the parent process has threads in more than one processor group, the new
        /// process inherits the group-relative affinity of an arbitrary group in use by the parent.
        /// </summary>
        INHERIT_PARENT_AFFINITY             = 0x00010000,

        /// <summary>
        /// The process is to be run as a protected process. The system restricts access to protected processes and the threads of
        /// protected processes.
        /// To activate a protected process, the binary must have a special signature.This signature is provided by Microsoft but not
        /// currently available for non-Microsoft binaries.There are currently four protected processes: media foundation, audio engine,
        /// Windows error reporting, and system. Components that load into these binaries must also be signed.Multimedia companies can
        /// leverage the first two protected processes.
        /// </summary>
        CREATE_PROTECTED_PROCESS            = 0x00040000,

        /// <summary>
        /// The process is created with extended startup information; the lpStartupInfo parameter specifies a STARTUPINFOEX structure.
        /// </summary>
        EXTENDED_STARTUPINFO_PRESENT        = 0x00080000,

        /// <summary>
        /// This flag allows secure processes, that run in the Virtualization-Based Security environment, to launch.
        /// </summary>
        CREATE_SECURE_PROCESS               = 0x00400000,

        /// <summary>
        /// The child processes of a process associated with a job are not associated with the job.
        /// If the calling process is not associated with a job, this constant has no effect. If the calling process is associated
        /// with a job, the job must set the JOB_OBJECT_LIMIT_BREAKAWAY_OK limit.
        /// </summary>
        CREATE_BREAKAWAY_FROM_JOB           = 0x01000000,

        /// <summary>
        /// The new process does not inherit the error mode of the calling process. Instead, the new process gets the default error
        /// mode.
        /// This feature is particularly useful for multithreaded shell applications that run with hard errors disabled.
        /// The default behavior is for the new process to inherit the error mode of the caller.Setting this flag changes that default
        /// behavior.
        /// </summary>
        CREATE_DEFAULT_ERROR_MODE           = 0x04000000,

        /// <summary>
        /// The process is a console application that is being run without a console window. Therefore, the console handle for the
        /// application is not set.
        /// This flag is ignored if the application is not a console application, or if it is used with either CREATE_NEW_CONSOLE or
        /// DETACHED_PROCESS.
        /// </summary>
        CREATE_NO_WINDOW                    = 0x08000000,

        /// <summary>
        /// Allows the caller to execute a child process that bypasses the process restrictions that would normally be applied
        /// automatically to the process.
        /// </summary>
        CREATE_PRESERVE_CODE_AUTHZ_LEVEL    = 0x02000000,
    }

    public enum Error : UInt32
    {
        OK                  = 0x00000000,
        AccessDenied        = 0x00000005,
        InvalidParameter    = 0x00000057,
        InsufficientBuffer  = 0x0000007A,
        AlreadyExists       = 0x000000B7,
    }

    public enum HResult : UInt32
    {
        OK                  = 0x00000000,
        AccessDenied        = Mask | Error.AccessDenied,
        InvalidParameter    = Mask | Error.InvalidParameter,
        InsufficientBuffer  = Mask | Error.InsufficientBuffer,
        AlreadyExists       = Mask | Error.AlreadyExists,

        Mask                = 0x80070000,
    }

    /// <summary>
    /// The information class for the limits to be set.
    /// </summary>
    public enum JOB_OBJECT_INFO_CLASS
    {
        /// <summary>
        /// The lpJobObjectInfo parameter is a pointer to a JOBOBJECT_BASIC_LIMIT_INFORMATION structure.
        /// </summary>
        JobObjectBasicLimitInformation              = 2,

        /// <summary>
        /// The lpJobObjectInfo parameter is a pointer to a JOBOBJECT_BASIC_UI_RESTRICTIONS structure.
        /// </summary>
        JobObjectBasicUIRestrictions                = 4,

        /// <summary>
        /// This flag is not supported. Applications must set security limitations individually for each process.
        /// </summary>
        JobObjectSecurityLimitInformation           = 5,

        /// <summary>
        /// The lpJobObjectInfo parameter is a pointer to a JOBOBJECT_END_OF_JOB_TIME_INFORMATION structure.
        /// </summary>
        JobObjectEndOfJobTimeInformation            = 6,

        /// <summary>
        /// The lpJobObjectInfo parameter is a pointer to a JOBOBJECT_ASSOCIATE_COMPLETION_PORT structure.
        /// </summary>
        JobObjectAssociateCompletionPortInformation = 7,

        /// <summary>
        /// The lpJobObjectInfo parameter is a pointer to a JOBOBJECT_EXTENDED_LIMIT_INFORMATION structure.
        /// </summary>
        JobObjectExtendedLimitInformation           = 9,

        /// <summary>
        /// The lpJobObjectInfo parameter is a pointer to a USHORT value that specifies the list of processor groups to assign the
        /// job to. The cbJobObjectInfoLength parameter is set to the size of the group data. Divide this value by sizeof(USHORT)
        /// to determine the number of groups.
        /// </summary>
        JobObjectGroupInformation                   = 11,

        /// <summary>
        /// The lpJobObjectInfo parameter is a pointer to a JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION structure.
        /// </summary>
        JobObjectNotificationLimitInformation       = 12,

        /// <summary>
        /// The lpJobObjectInfo parameter is a pointer to a buffer that contains an array of GROUP_AFFINITY structures that specify
        /// the affinity of the job for the processor groups to which the job is currently assigned. The cbJobObjectInfoLength
        /// parameter is set to the size of the group affinity data. Divide this value by sizeof(GROUP_AFFINITY) to determine the
        /// number of groups.
        /// </summary>
        JobObjectGroupInformationEx                 = 14,

        /// <summary>
        /// The lpJobObjectInfo parameter is a pointer to a JOBOBJECT_CPU_RATE_CONTROL_INFORMATION structure.
        /// </summary>
        JobObjectCpuRateControlInformation          = 15,

        /// <summary>
        /// The lpJobObjectInfo parameter is a pointer to a JOBOBJECT_NET_RATE_CONTROL_INFORMATION structure.
        /// </summary>
        JobObjectNetRateControlInformation          = 32,

        /// <summary>
        /// The lpJobObjectInfo parameter is a pointer to a JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION_2 structure.
        /// </summary>
        JobObjectNotificationLimitInformation2      = 34,

        /// <summary>
        /// The lpJobObjectInfo parameter is a pointer to a JOBOBJECT_LIMIT_VIOLATION_INFORMATION_2 structure.
        /// </summary>
        JobObjectLimitViolationInformation2         = 35,
    }

    [Flags]
    public enum JOB_OBJECT_LIMIT_FLAGS : UInt32
    {
        NONE                                        = 0x00000000,

        /// <summary>
        /// Causes all processes associated with the job to use the same minimum and maximum working set sizes. The MinimumWorkingSetSize
        /// and MaximumWorkingSetSize members contain additional information.
        /// If the job is nested, the effective working set size is the smallest working set size in the job chain.
        /// </summary>
        JOB_OBJECT_LIMIT_WORKINGSET                 = 0x00000001,

        /// <summary>
        /// Establishes a user-mode execution time limit for each currently active process and for all future processes associated with
        /// the job. The PerProcessUserTimeLimit member contains additional information.
        /// </summary>
        JOB_OBJECT_LIMIT_PROCESS_TIME               = 0x00000002,

        /// <summary>
        /// Establishes a user-mode execution time limit for the job. The PerJobUserTimeLimit member contains additional information.
        /// This flag cannot be used with JOB_OBJECT_LIMIT_PRESERVE_JOB_TIME.
        /// </summary>
        JOB_OBJECT_LIMIT_JOB_TIME                   = 0x00000004,

        /// <summary>
        /// Establishes a maximum number of simultaneously active processes associated with the job. The ActiveProcessLimit member
        /// contains additional information.
        /// </summary>
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS             = 0x00000008,

        /// <summary>
        /// Causes all processes associated with the job to use the same processor affinity. The Affinity member contains additional
        /// information.
        /// If the job is nested, the specified processor affinity must be a subset of the effective affinity of the parent job. If
        /// the specified affinity a superset of the affinity of the parent job, it is ignored and the affinity of the parent job
        /// is used.
        /// </summary>
        JOB_OBJECT_LIMIT_AFFINITY                   = 0x00000010,

        /// <summary>
        /// Causes all processes associated with the job to use the same priority class. The PriorityClass member contains additional
        /// information.
        /// If the job is nested, the effective priority class is the lowest priority class in the job chain.
        /// </summary>
        JOB_OBJECT_LIMIT_PRIORITY_CLASS             = 0x00000020,

        /// <summary>
        /// Preserves any job time limits you previously set. As long as this flag is set, you can establish a per-job time limit once,
        /// then alter other limits in subsequent calls. This flag cannot be used with JOB_OBJECT_LIMIT_JOB_TIME.
        /// </summary>
        JOB_OBJECT_LIMIT_PRESERVE_JOB_TIME          = 0x00000040,

        /// <summary>
        /// Causes all processes in the job to use the same scheduling class. The SchedulingClass member contains additional information.
        /// If the job is nested, the effective scheduling class is the lowest scheduling class in the job chain.
        /// </summary>
        JOB_OBJECT_LIMIT_SCHEDULING_CLASS           = 0x00000080,

        /// <summary>
        /// Causes all processes associated with the job to limit their committed memory. When a process attempts to commit memory that
        /// would exceed the per-process limit, it fails. If the job object is associated with a completion port, a
        /// JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT message is sent to the completion port.
        /// If the job is nested, the effective memory limit is the most restrictive memory limit in the job chain.
        /// This limit requires use of a JOBOBJECT_EXTENDED_LIMIT_INFORMATION structure. Its BasicLimitInformation member is a
        /// JOBOBJECT_BASIC_LIMIT_INFORMATION structure.
        /// </summary>
        JOB_OBJECT_LIMIT_PROCESS_MEMORY             = 0x00000100,

        /// <summary>
        /// Causes all processes associated with the job to limit the job-wide sum of their committed memory. When a process attempts
        /// to commit memory that would exceed the job-wide limit, it fails. If the job object is associated with a completion port,
        /// a JOB_OBJECT_MSG_JOB_MEMORY_LIMIT message is sent to the completion port.
        /// This limit requires use of a JOBOBJECT_EXTENDED_LIMIT_INFORMATION structure. Its BasicLimitInformation member is a
        /// JOBOBJECT_BASIC_LIMIT_INFORMATION structure.
        /// </summary>
        JOB_OBJECT_LIMIT_JOB_MEMORY                 = 0x00000200,

        /// <summary>
        /// Forces a call to the SetErrorMode function with the SEM_NOGPFAULTERRORBOX flag for each process associated with the job.
        /// If an exception occurs and the system calls the UnhandledExceptionFilter function, the debugger will be given a chance
        /// to act. If there is no debugger, the functions returns EXCEPTION_EXECUTE_HANDLER. Normally, this will cause termination
        /// of the process with the exception code as the exit status.
        /// This limit requires use of a JOBOBJECT_EXTENDED_LIMIT_INFORMATION structure. Its BasicLimitInformation member is a
        /// JOBOBJECT_BASIC_LIMIT_INFORMATION structure.
        /// </summary>
        JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400,

        /// <summary>
        /// If any process associated with the job creates a child process using the CREATE_BREAKAWAY_FROM_JOB flag while this limit
        /// is in effect, the child process is not associated with the job.
        /// This limit requires use of a JOBOBJECT_EXTENDED_LIMIT_INFORMATION structure. Its BasicLimitInformation member is a
        /// JOBOBJECT_BASIC_LIMIT_INFORMATION structure.
        /// </summary>
        JOB_OBJECT_LIMIT_BREAKAWAY_OK               = 0x00000800,

        /// <summary>
        /// Allows any process associated with the job to create child processes that are not associated with the job.
        /// If the job is nested and its immediate job object allows breakaway, the child process breaks away from the immediate job
        /// object and from each job in the parent job chain, moving up the hierarchy until it reaches a job that does not permit
        /// breakaway. If the immediate job object does not allow breakaway, the child process does not break away even if jobs in its
        /// parent job chain allow it.
        /// This limit requires use of a JOBOBJECT_EXTENDED_LIMIT_INFORMATION structure. Its BasicLimitInformation member is a
        /// JOBOBJECT_BASIC_LIMIT_INFORMATION structure.
        /// </summary>
        JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK        = 0x00001000,

        /// <summary>
        /// Causes all processes associated with the job to terminate when the last handle to the job is closed.
        /// This limit requires use of a JOBOBJECT_EXTENDED_LIMIT_INFORMATION structure. Its BasicLimitInformation member is a
        /// JOBOBJECT_BASIC_LIMIT_INFORMATION structure.
        /// </summary>
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE          = 0x00002000,

        /// <summary>
        /// Allows processes to use a subset of the processor affinity for all processes associated with the job. This value
        /// must be combined with JOB_OBJECT_LIMIT_AFFINITY.
        /// </summary>
        JOB_OBJECT_LIMIT_SUBSET_AFFINITY            = 0x00004000,
    }

    [Flags]
    public enum JOB_OBJECT_UILIMIT_FLAGS : UInt32
    {
        NONE                                = 0x00000000,
        ALL                                 = 0x000000FF,

        /// <summary>
        /// Prevents processes associated with the job from using USER handles owned by processes not associated with the same job.
        /// </summary>
        JOB_OBJECT_UILIMIT_HANDLES          = 0x00000001,

        /// <summary>
        /// Prevents processes associated with the job from reading data from the clipboard.
        /// </summary>
        JOB_OBJECT_UILIMIT_READCLIPBOARD    = 0x00000002,

        /// <summary>
        /// Prevents processes associated with the job from writing data to the clipboard.
        /// </summary>
        JOB_OBJECT_UILIMIT_WRITECLIPBOARD   = 0x00000004,

        /// <summary>
        /// Prevents processes associated with the job from changing system parameters by using the SystemParametersInfo function.
        /// </summary>
        JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS = 0x00000008,

        /// <summary>
        /// Prevents processes associated with the job from calling the ChangeDisplaySettings function.
        /// </summary>
        JOB_OBJECT_UILIMIT_DISPLAYSETTINGS  = 0x00000010,

        /// <summary>
        /// Prevents processes associated with the job from accessing global atoms. When this flag is used, each job has its own atom table.
        /// </summary>
        JOB_OBJECT_UILIMIT_GLOBALATOMS      = 0x00000020,

        /// <summary>
        /// Prevents processes associated with the job from creating desktops and switching desktops using the CreateDesktop and
        /// SwitchDesktop functions.
        /// </summary>
        JOB_OBJECT_UILIMIT_DESKTOP          = 0x00000040,

        /// <summary>
        /// Prevents processes associated with the job from calling the ExitWindows or ExitWindowsEx function.
        /// </summary>
        JOB_OBJECT_UILIMIT_EXITWINDOWS      = 0x00000080,
    }

    public enum ProcThreadAttribute : UInt32
    {
        ParentProcess           = 0x00020000,
        HandleList              = 0x00020002,
        SecurityCapabilities    = 0x00020009,
    }

    [Flags]
    public enum STARTUPINFO_FLAGS : UInt32
    {
        NONE                    = 0x00000000,

        /// <summary>
        /// The wShowWindow member contains additional information.
        /// </summary>
        STARTF_USESHOWWINDOW    = 0x00000001,

        /// <summary>
        /// The dwXSize and dwYSize members contain additional information.
        /// </summary>
        STARTF_USESIZE          = 0x00000002,

        /// <summary>
        /// The dwX and dwY members contain additional information.
        /// </summary>
        STARTF_USEPOSITION      = 0x00000004,

        /// <summary>
        /// The dwXCountChars and dwYCountChars members contain additional information.
        /// </summary>
        STARTF_USECOUNTCHARS    = 0x00000008,

        /// <summary>
        /// The dwFillAttribute member contains additional information.
        /// </summary>
        STARTF_USEFILLATTRIBUTE = 0x00000010,

        /// <summary>
        /// Indicates that the process should be run in full-screen mode, rather than in windowed mode.
        /// This flag is only valid for console applications running on an x86 computer.
        /// </summary>
        STARTF_RUNFULLSCREEN    = 0x00000020,

        /// <summary>
        /// Indicates that the cursor is in feedback mode for two seconds after CreateProcess is called. The Working in Background
        /// cursor is displayed (see the Pointers tab in the Mouse control panel utility).
        /// If during those two seconds the process makes the first GUI call, the system gives five more seconds to the process. If
        /// during those five seconds the process shows a window, the system gives five more seconds to the process to finish
        /// drawing the window.
        /// The system turns the feedback cursor off after the first call to GetMessage, regardless of whether the process is drawing.
        /// </summary>
        STARTF_FORCEONFEEDBACK  = 0x00000040,

        /// <summary>
        /// Indicates that the feedback cursor is forced off while the process is starting. The Normal Select cursor is displayed.
        /// </summary>
        STARTF_FORCEOFFFEEDBACK = 0x00000080,

        /// <summary>
        /// The hStdInput, hStdOutput, and hStdError members contain additional information.
        /// If this flag is specified when calling one of the process creation functions, the handles must be inheritable and the
        /// function's bInheritHandles parameter must be set to TRUE.
        /// If this flag is specified when calling the GetStartupInfo function, these members are either the handle value specified
        /// during process creation or INVALID_HANDLE_VALUE.
        /// Handles must be closed with CloseHandle when they are no longer needed.
        /// This flag cannot be used with STARTF_USEHOTKEY.
        /// </summary>
        STARTF_USESTDHANDLES    = 0x00000100,

        /// <summary>
        /// The hStdInput member contains additional information.
        /// This flag cannot be used with STARTF_USESTDHANDLES.
        /// </summary>
        STARTF_USEHOTKEY        = 0x00000200,

        /// <summary>
        /// The lpTitle member contains the path of the shortcut file (.lnk) that the user invoked to start this process. This is
        /// typically set by the shell when a .lnk file pointing to the launched application is invoked. Most applications will
        /// not need to set this value.
        /// This flag cannot be used with STARTF_TITLEISAPPID.
        /// </summary>
        STARTF_TITLEISLINKNAME  = 0x00000800,

        /// <summary>
        /// The lpTitle member contains an AppUserModelID. This identifier controls how the taskbar and Start menu present the
        /// application, and enables it to be associated with the correct shortcuts and Jump Lists. Generally, applications will
        /// use the SetCurrentProcessExplicitAppUserModelID and GetCurrentProcessExplicitAppUserModelID functions instead of
        /// setting this flag. For more information, see Application User Model IDs.
        /// If STARTF_PREVENTPINNING is used, application windows cannot be pinned on the taskbar. The use of any
        /// AppUserModelID-related window properties by the application overrides this setting for that window only.
        /// This flag cannot be used with STARTF_TITLEISLINKNAME.
        /// </summary>
        STARTF_TITLEISAPPID     = 0x00001000,

        /// <summary>
        /// Indicates that any windows created by the process cannot be pinned on the taskbar.
        /// This flag must be combined with STARTF_TITLEISAPPID.
        /// </summary>
        STARTF_PREVENTPINNING   = 0x00002000,

        /// <summary>
        /// The command line came from an untrusted source.
        /// </summary>
        STARTF_UNTRUSTEDSOURCE  = 0x00008000,
    }
}
