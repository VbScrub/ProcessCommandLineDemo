Imports System.Runtime.InteropServices
Imports System.Net.Sockets
Imports System.ComponentModel

Public Class WindowsApi

    Public Shared Function Is32BitProcessOn64BitOs(ByVal TargetProcess As Process) As Boolean
        Dim IsWow64 As Boolean = False
        If MethodExistsInDll("kernel32.dll", "IsWow64Process") Then
            Win32.IsWow64Process(TargetProcess.Handle, IsWow64)
        End If
        Return IsWow64
    End Function

    Public Shared Function MethodExistsInDll(ByVal ModuleName As String, ByVal MethodName As String) As Boolean
        Dim ModuleHandle As IntPtr = Win32.GetModuleHandle(ModuleName)
        If ModuleHandle = IntPtr.Zero Then
            Return False
        End If
        Return (Win32.GetProcAddress(ModuleHandle, MethodName) <> IntPtr.Zero)
    End Function

    Public Shared Function GetCommandLine(ByVal TargetProcess As Process) As String
        'If we're on a 64 bit OS then the target process will have a 64 bit PEB if we are calling this function from a 64 bit process (regardless of
        'whether or not the target process is 32 bit or 64 bit).
        'If we are calling this function from a 32 bit process and the target process is 32 bit then we will get a 32 bit PEB, even on a 64 bit OS. 
        'The one situation we can't handle is if we are calling this function from a 32 bit process and the target process is 64 bit. For that we need to use the
        'undocumented NtWow64QueryInformationProcess64 and NtWow64ReadVirtualMemory64 APIs
        Dim Is64BitPeb As Boolean = False
        If Environment.Is64BitOperatingSystem() Then
            If Is32BitProcessOn64BitOs(Process.GetCurrentProcess) Then
                If Not Is32BitProcessOn64BitOs(TargetProcess) Then
                    'TODO: Use NtWow64ReadVirtualMemory64 to read from 64 bit processes when we are a 32 bit process instead of throwing this exception
                    Throw New InvalidOperationException("This function cannot be used against a 64 bit process when the calling process is 32 bit")
                End If
            Else
                Is64BitPeb = True
            End If
        End If

        'Open the target process for memory reading
        Using MemoryReader As New ProcessMemoryReader(TargetProcess)
            Dim ProcessInfo As Win32.PROCESS_BASIC_INFORMATION = Nothing
            'Get basic information about the process, including the PEB address
            Dim Result As Integer = Win32.NtQueryInformationProcess(TargetProcess.Handle, 0, ProcessInfo, Marshal.SizeOf(ProcessInfo), 0)
            If Not Result = 0 Then
                Throw New System.ComponentModel.Win32Exception(Win32.RtlNtStatusToDosError(Result))
            End If
            'Get pointer from the ProcessParameters member of the PEB (PEB has different structure on x86 vs x64 so different structures needed for each)
            Dim PebLength As Integer
            If Is64BitPeb Then
                PebLength = Marshal.SizeOf(GetType(Win32.PEB_64))
            Else
                PebLength = Marshal.SizeOf(GetType(Win32.PEB_32))
            End If
            'Read the PEB from the PebBaseAddress pointer
            'NOTE: This pointer points to memory in the target process' address space, so Marshal.PtrToStructure won't work. We have to read it with the ReadProcessMemory API 
            Dim PebBytes() As Byte = MemoryReader.Read(ProcessInfo.PebBaseAddress, PebLength)
            'Using GCHandle.Alloc get a pointer to the byte array we read from the target process, so we can use PtrToStructure to convert those bytes to our PEB_32 or PEB_64 structure
            Dim PebBytesPtr As GCHandle = GCHandle.Alloc(PebBytes, GCHandleType.Pinned)
            Try
                Dim ProcParamsPtr As IntPtr
                'Get a pointer to the RTL_USER_PROCESS_PARAMETERS structure (again this pointer refers to the target process' memory)
                If Is64BitPeb Then
                    Dim PEB As Win32.PEB_64 = GcHandleToStruct(Of Win32.PEB_64)(PebBytesPtr.AddrOfPinnedObject)
                    ProcParamsPtr = PEB.ProcessParameters
                Else
                    Dim PEB As Win32.PEB_32 = GcHandleToStruct(Of Win32.PEB_32)(PebBytesPtr.AddrOfPinnedObject)
                    ProcParamsPtr = PEB.ProcessParameters
                End If
                'Now that we've got the pointer from the ProcessParameters member, we read the RTL_USER_PROCESS_PARAMETERS structure that is stored at that location in the target process' memory
                Dim ProcParamsBytes() As Byte = MemoryReader.Read(ProcParamsPtr, Marshal.SizeOf(GetType(Win32.RTL_USER_PROCESS_PARAMETERS)))
                'Again we use GCHandle.Alloc to get a pointer to the byte array we just read
                Dim ProcParamsBytesPtr As GCHandle = GCHandle.Alloc(ProcParamsBytes, GCHandleType.Pinned)
                Try
                    'Convert the byte array to a RTL_USER_PROCESS_PARAMETERS structure
                    Dim ProcParams As Win32.RTL_USER_PROCESS_PARAMETERS = GcHandleToStruct(Of Win32.RTL_USER_PROCESS_PARAMETERS)(ProcParamsBytesPtr.AddrOfPinnedObject)
                    'Get the CommandLine member of the RTL_USER_PROCESS_PARAMETERS structure
                    Dim CmdLineUnicodeString As Win32.UNICODE_STRING = ProcParams.CommandLine
                    'The Buffer member of the UNICODE_STRING structure points to the actual command line string we want, so we read from the location that points to
                    Dim CmdLineBytes() As Byte = MemoryReader.Read(CmdLineUnicodeString.Buffer, CmdLineUnicodeString.Length)
                    'Convert the bytes to a regular .NET String and return it
                    Return System.Text.Encoding.Unicode.GetString(CmdLineBytes)
                Finally
                    'Clean up the GCHandle we created for the RTL_USER_PROCESS_PARAMETERS bytes
                    If ProcParamsBytesPtr.IsAllocated Then
                        ProcParamsBytesPtr.Free()
                    End If
                End Try
            Finally
                'Clean up the GCHandle we created for the PEB bytes
                If PebBytesPtr.IsAllocated Then
                    PebBytesPtr.Free()
                End If
            End Try
        End Using
    End Function

    'Using this generic function just to make the code in the GetCommandLine function easier to read and save some casting 
    Private Shared Function GcHandleToStruct(Of T)(Pointer As IntPtr) As T
        Return DirectCast(Marshal.PtrToStructure(Pointer, GetType(T)), T)
    End Function

    Public Class Win32

        <StructLayout(LayoutKind.Sequential)>
        Public Structure UNICODE_STRING
            Public Length As UInt16
            Public MaximumLength As UInt16
            '64 bit version of this actually has 4 bytes of padding here (after MaximumLength and before Buffer), but the default Pack size for structs handles this for us
            Public Buffer As IntPtr
        End Structure

        <StructLayout(LayoutKind.Sequential)>
        Public Structure RTL_USER_PROCESS_PARAMETERS
            <MarshalAs(UnmanagedType.ByValArray, SizeConst:=16)>
            Public Reserved1() As Byte
            <MarshalAs(UnmanagedType.ByValArray, SizeConst:=10)>
            Public Reserved2() As IntPtr
            Public ImagePathName As UNICODE_STRING
            Public CommandLine As UNICODE_STRING
        End Structure

        <StructLayout(LayoutKind.Sequential)>
        Public Structure PEB_32
            <MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst:=2)>
            Public Reserved1() As Byte
            Public BeingDebugged As Byte
            <MarshalAs(UnmanagedType.ByValArray, SizeConst:=1)> _
            Public Reserved2() As Byte
            <MarshalAs(UnmanagedType.ByValArray, SizeConst:=2)> _
            Public Reserved3() As IntPtr
            Public Ldr As IntPtr
            Public ProcessParameters As IntPtr
            <MarshalAs(UnmanagedType.ByValArray, SizeConst:=3)> _
            Public Reserved4() As IntPtr
            Public AtlThunkSListPtr As IntPtr
            Public Reserved5 As IntPtr
            Public Reserved6 As UInteger
            Public Reserved7 As IntPtr
            Public Reserved8 As UInteger
            Public AtlThunkSListPtr32 As UInteger
            <MarshalAs(UnmanagedType.ByValArray, SizeConst:=45)> _
            Public Reserved9() As IntPtr
            <MarshalAs(UnmanagedType.ByValArray, SizeConst:=96)> _
            Public Reserved10() As Byte
            Public PostProcessInitRoutine As IntPtr
            <MarshalAs(UnmanagedType.ByValArray, SizeConst:=128)> _
            Public Reserved11() As Byte
            <MarshalAs(UnmanagedType.ByValArray, SizeConst:=1)> _
            Public Reserved12() As IntPtr
            Public SessionId As UInteger
        End Structure

        <StructLayout(LayoutKind.Sequential)>
        Public Structure PEB_64
            <MarshalAs(UnmanagedType.ByValArray, SizeConst:=2)>
            Public Reserved1() As Byte
            Public BeingDebugged As Byte
            <MarshalAs(UnmanagedType.ByValArray, SizeConst:=21)>
            Public Reserved2() As Byte
            Public LoaderData As IntPtr
            Public ProcessParameters As IntPtr
            <MarshalAs(UnmanagedType.ByValArray, SizeConst:=520)>
            Public Reserved3() As Byte
            Public PostProcessInitRoutine As IntPtr
            <MarshalAs(UnmanagedType.ByValArray, SizeConst:=136)>
            Public Reserved4() As Byte
            Public SessionId As UInteger
        End Structure

        <StructLayout(LayoutKind.Sequential)>
        Public Structure PROCESS_BASIC_INFORMATION
            Public Reserved1 As IntPtr
            Public PebBaseAddress As IntPtr
            <MarshalAs(UnmanagedType.ByValArray, SizeConst:=2)>
            Public Reserved2() As IntPtr
            Public UniqueProcessID As IntPtr
            Public Reserved3 As IntPtr
        End Structure

        <Flags()>
        Public Enum ProcessAccess As UInteger
            AllAccess = CreateThread Or DuplicateHandle Or QueryInformation Or SetInformation Or Terminate Or VMOperation Or VMRead Or VMWrite Or Synchronize
            CreateThread = &H2
            DuplicateHandle = &H40
            QueryInformation = &H400
            QueryLimitedInformation = &H1000
            SetInformation = &H200
            Terminate = &H1
            VMOperation = &H8
            VMRead = &H10
            VMWrite = &H20
            Synchronize = &H100000
        End Enum

        <DllImport("ntdll.dll", EntryPoint:="RtlNtStatusToDosError", SetLastError:=True)> _
        Public Shared Function RtlNtStatusToDosError(NtStatus As Integer) As Integer
        End Function

        <DllImport("kernel32.dll", EntryPoint:="IsWow64Process", SetLastError:=True)> _
        Public Shared Function IsWow64Process(ByVal hProcess As IntPtr, <Out()> ByRef Wow64Process As Boolean) As <MarshalAs(UnmanagedType.Bool)> Boolean
        End Function

        <DllImport("kernel32.dll", EntryPoint:="GetModuleHandle", SetLastError:=True)> _
        Public Shared Function GetModuleHandle(ByVal ModuleName As String) As IntPtr
        End Function

        <DllImport("kernel32.dll", EntryPoint:="GetProcAddress", SetLastError:=True)> _
        Public Shared Function GetProcAddress(ByVal hModule As IntPtr, ByVal MethodName As String) As IntPtr
        End Function

        <DllImport("ntdll.dll", EntryPoint:="NtQueryInformationProcess", SetLastError:=True)>
        Public Shared Function NtQueryInformationProcess(ByVal handle As IntPtr,
                                                         ByVal Processinformationclass As UInteger,
                                                         ByRef ProcessInformation As PROCESS_BASIC_INFORMATION,
                                                         ByVal ProcessInformationLength As Integer,
                                                         ByRef ReturnLength As UInteger) As Integer
        End Function

        <DllImport("kernel32.dll", EntryPoint:="ReadProcessMemory", SetLastError:=True)> _
        Public Shared Function ReadProcessMemory(ByVal hProcess As IntPtr,
                                                 ByVal lpBaseAddress As IntPtr,
                                                 <Out()> ByVal lpBuffer As Byte(),
                                                 ByVal nSize As UInteger,
                                                 <Out()> ByRef lpNumberOfBytesRead As UInteger) As <MarshalAs(UnmanagedType.Bool)> Boolean
        End Function

        <DllImport("kernel32.dll", EntryPoint:="OpenProcess", SetLastError:=True)> _
        Public Shared Function OpenProcess(ByVal dwDesiredAccess As ProcessAccess,
                                           <MarshalAs(UnmanagedType.Bool)> ByVal bInheritHandle As Boolean,
                                           ByVal dwProcessId As UInteger) As IntPtr
        End Function

        <DllImport("kernel32.dll", EntryPoint:="CloseHandle", SetLastError:=True)> _
        Public Shared Function CloseHandle(ByVal Handle As IntPtr) As <MarshalAs(UnmanagedType.Bool)> Boolean
        End Function


    End Class




End Class
