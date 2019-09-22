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
    /// <summary>
    /// Contains I/O accounting information for a process or a job object. For a job object, the counters include all operations
    /// performed by all processes that have ever been associated with the job, in addition to all processes currently associated
    /// with the job.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct IO_COUNTERS
    {
        /// <summary>
        /// The number of read operations performed.
        /// </summary>
        public UInt64 ReadOperationCount;

        /// <summary>
        /// The number of write operations performed.
        /// </summary>
        public UInt64 WriteOperationCount;

        /// <summary>
        /// The number of I/O operations performed, other than read and write operations.
        /// </summary>
        public UInt64 OtherOperationCount;

        /// <summary>
        /// The number of bytes read.
        /// </summary>
        public UInt64 ReadTransferCount;

        /// <summary>
        /// The number of bytes written.
        /// </summary>
        public UInt64 WriteTransferCount;

        /// <summary>
        /// The number of bytes transferred during operations other than read and write operations.
        /// </summary>
        public UInt64 OtherTransferCount;
    }

    /// <summary>
    /// Contains basic limit information for a job object.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        /// <summary>
        /// If LimitFlags specifies JOB_OBJECT_LIMIT_PROCESS_TIME, this member is the per-process user-mode execution time limit,
        /// in 100-nanosecond ticks. Otherwise, this member is ignored.
        /// The system periodically checks to determine whether each process associated with the job has accumulated more user-mode
        /// time than the set limit.If it has, the process is terminated.
        /// If the job is nested, the effective limit is the most restrictive limit in the job chain.
        /// </summary>
        public Int64 PerProcessUserTimeLimit;

        /// <summary>
        /// If LimitFlags specifies JOB_OBJECT_LIMIT_JOB_TIME, this member is the per-job user-mode execution time limit, in
        /// 100-nanosecond ticks. Otherwise, this member is ignored.
        /// The system adds the current time of the processes associated with the job to this limit.For example, if you set
        /// this limit to 1 minute, and the job has a process that has accumulated 5 minutes of user-mode time, the limit
        /// actually enforced is 6 minutes.
        /// The system periodically checks to determine whether the sum of the user-mode execution time for all processes is
        /// greater than this end-of-job limit.If it is, the action specified in the EndOfJobTimeAction member of the
        /// JOBOBJECT_END_OF_JOB_TIME_INFORMATION structure is carried out. By default, all processes are terminated and the
        /// status code is set to ERROR_NOT_ENOUGH_QUOTA.
        /// To register for notification when this limit is exceeded without terminating processes, use the SetInformationJobObject
        /// function with the JobObjectNotificationLimitInformation information class.
        /// </summary>
        public Int64 PerJobUserTimeLimit;

        /// <summary>
        /// The limit flags that are in effect. This member is a bitfield that determines whether other structure members are used.
        /// Any combination of values can be specified.
        /// </summary>
        public JOB_OBJECT_LIMIT_FLAGS LimitFlags;

        /// <summary>
        /// If LimitFlags specifies JOB_OBJECT_LIMIT_WORKINGSET, this member is the minimum working set size in bytes for each process
        /// associated with the job. Otherwise, this member is ignored.
        /// If MaximumWorkingSetSize is nonzero, MinimumWorkingSetSize cannot be zero.
        /// </summary>
        public UIntPtr MinimumWorkingSetSize;

        /// <summary>
        /// If LimitFlags specifies JOB_OBJECT_LIMIT_WORKINGSET, this member is the maximum working set size in bytes for each process
        /// associated with the job. Otherwise, this member is ignored.
        /// If MinimumWorkingSetSize is nonzero, MaximumWorkingSetSize cannot be zero.
        /// </summary>
        public UIntPtr MaximumWorkingSetSize;

        /// <summary>
        /// If LimitFlags specifies JOB_OBJECT_LIMIT_ACTIVE_PROCESS, this member is the active process limit for the job. Otherwise,
        /// this member is ignored.
        /// If you try to associate a process with a job, and this causes the active process count to exceed this limit, the process
        /// is terminated and the association fails.
        /// </summary>
        public UInt32 ActiveProcessLimit;

        /// <summary>
        /// If LimitFlags specifies JOB_OBJECT_LIMIT_AFFINITY, this member is the processor affinity for all processes associated with
        /// the job. Otherwise, this member is ignored.
        /// The affinity must be a subset of the system affinity mask obtained by calling the GetProcessAffinityMask function.The affinity
        /// of each thread is set to this value, but threads are free to subsequently set their affinity, as long as it is a subset of the
        /// specified affinity mask.Processes cannot set their own affinity mask.
        /// </summary>
        public UIntPtr Affinity;

        /// <summary>
        /// If LimitFlags specifies JOB_OBJECT_LIMIT_PRIORITY_CLASS, this member is the priority class for all processes associated with
        /// the job. Otherwise, this member is ignored.
        /// Processes and threads cannot modify their priority class. The calling process must enable the SE_INC_BASE_PRIORITY_NAME privilege.
        /// </summary>
        public UInt32 PriorityClass;

        /// <summary>
        /// If LimitFlags specifies JOB_OBJECT_LIMIT_SCHEDULING_CLASS, this member is the scheduling class for all processes associated
        /// with the job. Otherwise, this member is ignored.
        /// The valid values are 0 to 9. Use 0 for the least favorable scheduling class relative to other threads, and 9 for the most
        /// favorable scheduling class relative to other threads.By default, this value is 5. To use a scheduling class greater than 5,
        /// the calling process must enable the SE_INC_BASE_PRIORITY_NAME privilege.
        /// </summary>
        public UInt32 SchedulingClass;
    }

    /// <summary>
    /// Contains basic user-interface restrictions for a job object.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct JOBOBJECT_BASIC_UI_RESTRICTIONS
    {
        /// <summary>
        /// The restriction class for the user interface.
        /// </summary>
        public JOB_OBJECT_UILIMIT_FLAGS UIRestrictionsClass;
    }

    /// <summary>
    /// Contains basic and extended limit information for a job object.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        /// <summary>
        /// A JOBOBJECT_BASIC_LIMIT_INFORMATION structure that contains basic limit information.
        /// </summary>
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;

        /// <summary>
        /// Reserved.
        /// </summary>
        public IO_COUNTERS IoInfo;

        /// <summary>
        /// If the LimitFlags member of the JOBOBJECT_BASIC_LIMIT_INFORMATION structure specifies the JOB_OBJECT_LIMIT_PROCESS_MEMORY
        /// value, this member specifies the limit for the virtual memory that can be committed by a process. Otherwise, this member
        /// is ignored.
        /// </summary>
        public UIntPtr ProcessMemoryLimit;

        /// <summary>
        /// If the LimitFlags member of the JOBOBJECT_BASIC_LIMIT_INFORMATION structure specifies the JOB_OBJECT_LIMIT_JOB_MEMORY value,
        /// this member specifies the limit for the virtual memory that can be committed for the job. Otherwise, this member is ignored.
        /// </summary>
        public UIntPtr JobMemoryLimit;

        /// <summary>
        /// The peak memory used by any process ever associated with the job.
        /// </summary>
        public UIntPtr PeakProcessMemoryUsed;

        /// <summary>
        /// The peak memory usage of all processes currently associated with the job.
        /// </summary>
        public UIntPtr PeakJobMemoryUsed;
    }

    /// <summary>
    /// Contains information about a newly created process and its primary thread.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        /// <summary>
        /// A handle to the newly created process. The handle is used to specify the process in all functions that perform operations
        /// on the process object.
        /// </summary>
        public IntPtr hProcess;

        /// <summary>
        /// A handle to the primary thread of the newly created process. The handle is used to specify the thread in all functions
        /// that perform operations on the thread object.
        /// </summary>
        public IntPtr hThread;

        /// <summary>
        /// A value that can be used to identify a process. The value is valid from the time the process is created until all handles
        /// to the process are closed and the process object is freed; at this point, the identifier may be reused.
        /// </summary>
        public int dwProcessId;

        /// <summary>
        /// A value that can be used to identify a thread. The value is valid from the time the thread is created until all handles
        /// to the thread are closed and the thread object is freed; at this point, the identifier may be reused.
        /// </summary>
        public int dwThreadId;
    }

    /// <summary>
    /// Defines the security capabilities of the app container.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct SECURITY_CAPABILITIES
    {
        /// <summary>
        /// The SID of the AppContainer.
        /// NOTE: Cannot be SafeSecurityIdentifier to avoid issues with Marshal.StructureToPtr.
        /// </summary>
        public IntPtr AppContainerSid;
        public IntPtr Capabilities;
        public Int32 CapabilityCount;
        public Int32 Reserved;
    }

    /// <summary>
    /// The SID_AND_ATTRIBUTES structure represents a security identifier (SID) and its attributes. SIDs are used to uniquely
    /// identify users or groups.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct SID_AND_ATTRIBUTES
    {
        /// <summary>
        /// The SID for which the attributes are applicable.
        /// NOTE: Cannot be SafeSecurityIdentifier to avoid issues with Marshal.StructureToPtr.
        /// </summary>
        public IntPtr Sid;

        /// <summary>
        /// Contains up to 32 one-bit flags. The meaning depends on the definition and use of the SID.
        /// </summary>
        public SID_ATTRIBUTES Attributes;
    }

    /// <summary>
    /// Specifies the window station, desktop, standard handles, and appearance of the main window for a process at creation time.
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        /// <summary>
        /// The size of the structure, in bytes.
        /// </summary>
        public Int32 cb;

        /// <summary>
        /// Reserved; must be NULL.
        /// </summary>
        public string lpReserved;

        /// <summary>
        /// The name of the desktop, or the name of both the desktop and window station for this process. A backslash in the string
        /// indicates that the string includes both the desktop and window station names.
        /// </summary>
        public string lpDesktop;

        /// <summary>
        /// For console processes, this is the title displayed in the title bar if a new console window is created. If NULL, the name
        /// of the executable file is used as the window title instead. This parameter must be NULL for GUI or console processes that
        /// do not create a new console window.
        /// </summary>
        public string lpTitle;

        /// <summary>
        /// If dwFlags specifies STARTF_USEPOSITION, this member is the x offset of the upper left corner of a window if a new window is
        /// created, in pixels. Otherwise, this member is ignored.
        /// The offset is from the upper left corner of the screen.For GUI processes, the specified position is used the first time the
        /// new process calls CreateWindow to create an overlapped window if the x parameter of CreateWindow is CW_USEDEFAULT.
        /// </summary>
        public Int32 dwX;

        /// <summary>
        /// If dwFlags specifies STARTF_USEPOSITION, this member is the y offset of the upper left corner of a window if a new window is
        /// created, in pixels. Otherwise, this member is ignored.
        /// The offset is from the upper left corner of the screen.For GUI processes, the specified position is used the first time the
        /// new process calls CreateWindow to create an overlapped window if the y parameter of CreateWindow is CW_USEDEFAULT.
        /// </summary>
        public Int32 dwY;

        /// <summary>
        /// If dwFlags specifies STARTF_USESIZE, this member is the width of the window if a new window is created, in pixels. Otherwise,
        /// this member is ignored.
        /// For GUI processes, this is used only the first time the new process calls CreateWindow to create an overlapped window if the
        /// nWidth parameter of CreateWindow is CW_USEDEFAULT.
        /// </summary>
        public Int32 dwXSize;

        /// <summary>
        /// If dwFlags specifies STARTF_USESIZE, this member is the height of the window if a new window is created, in pixels. Otherwise,
        /// this member is ignored.
        /// For GUI processes, this is used only the first time the new process calls CreateWindow to create an overlapped window if the
        /// nHeight parameter of CreateWindow is CW_USEDEFAULT.
        /// </summary>
        public Int32 dwYSize;

        /// <summary>
        /// If dwFlags specifies STARTF_USECOUNTCHARS, if a new console window is created in a console process, this member specifies the
        /// screen buffer width, in character columns. Otherwise, this member is ignored.
        /// </summary>
        public Int32 dwXCountChars;

        /// <summary>
        /// If dwFlags specifies STARTF_USECOUNTCHARS, if a new console window is created in a console process, this member specifies the
        /// screen buffer height, in character rows. Otherwise, this member is ignored.
        /// </summary>
        public Int32 dwYCountChars;

        /// <summary>
        /// If dwFlags specifies STARTF_USEFILLATTRIBUTE, this member is the initial text and background colors if a new console window is
        /// created in a console application. Otherwise, this member is ignored.
        /// This value can be any combination of the following values: FOREGROUND_BLUE, FOREGROUND_GREEN, FOREGROUND_RED, FOREGROUND_INTENSITY,
        /// BACKGROUND_BLUE, BACKGROUND_GREEN, BACKGROUND_RED, and BACKGROUND_INTENSITY.
        /// </summary>
        public Int32 dwFillAttribute;

        /// <summary>
        /// A bitfield that determines whether certain STARTUPINFO members are used when the process creates a window. This member can be one or
        /// more values.
        /// </summary>
        public STARTUPINFO_FLAGS dwFlags;

        /// <summary>
        /// If dwFlags specifies STARTF_USESHOWWINDOW, this member can be any of the values that can be specified in the nCmdShow parameter
        /// for the ShowWindow function, except for SW_SHOWDEFAULT. Otherwise, this member is ignored.
        /// For GUI processes, the first time ShowWindow is called, its nCmdShow parameter is ignored wShowWindow specifies the default value.
        /// In subsequent calls to ShowWindow, the wShowWindow member is used if the nCmdShow parameter of ShowWindow is set to SW_SHOWDEFAULT.
        /// </summary>
        public Int16 wShowWindow;

        /// <summary>
        /// Reserved for use by the C Run-time; must be zero.
        /// </summary>
        public Int16 cbReserved2;

        /// <summary>
        /// Reserved for use by the C Run-time; must be NULL.
        /// </summary>
        public IntPtr lpReserved2;

        /// <summary>
        /// If dwFlags specifies STARTF_USESTDHANDLES, this member is the standard input handle for the process. If
        /// STARTF_USESTDHANDLES is not specified, the default for standard input is the keyboard buffer.
        /// If dwFlags specifies STARTF_USEHOTKEY, this member specifies a hotkey value that is sent as the wParam parameter
        /// of a WM_SETHOTKEY message to the first eligible top-level window created by the application that owns the process. If
        /// the window is created with the WS_POPUP window style, it is not eligible unless the WS_EX_APPWINDOW extended window
        /// style is also set.
        /// Otherwise, this member is ignored.
        /// </summary>
        public IntPtr hStdInput;

        /// <summary>
        /// If dwFlags specifies STARTF_USESTDHANDLES, this member is the standard output handle for the process. Otherwise,
        /// this member is ignored and the default for standard output is the console window's buffer.
        /// If a process is launched from the taskbar or jump list, the system sets hStdOutput to a handle to the monitor that
        /// contains the taskbar or jump list used to launch the process
        /// </summary>
        public IntPtr hStdOutput;

        /// <summary>
        /// If dwFlags specifies STARTF_USESTDHANDLES, this member is the standard error handle for the process. Otherwise, this
        /// member is ignored and the default for standard error is the console window's buffer.
        /// </summary>
        public IntPtr hStdError;

        public void Init()
        {
            this.cb = Marshal.SizeOf(typeof(STARTUPINFO));
        }
    }

    /// <summary>
    /// Specifies the window station, desktop, standard handles, and attributes for a new process.
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFOEX
    {
        /// <summary>
        /// A STARTUPINFO structure.
        /// </summary>
        public STARTUPINFO StartupInfo;

        /// <summary>
        /// An attribute list. This list is created by the InitializeProcThreadAttributeList function.
        /// </summary>
        public IntPtr lpAttributeList;

        public void Init()
        {
            this.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
        }
    }
}
