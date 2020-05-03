Imports System.Runtime.InteropServices
Imports System.Net.Sockets
Imports System.ComponentModel

Public Class WindowsApi

    Public Shared Function Is64BitOperatingSystem() As Boolean
        If IntPtr.Size = 8 Then
            Return True
        Else
            Return Is32BitProcessOn64BitOs(Process.GetCurrentProcess)
        End If
    End Function

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
        'whether or not the target process is 32 bit or 64 bit). But if we are calling this function from a 32 bit process and the target process is 
        '32 bit then we will get a 32 bit PEB even on a 64 bit OS. The one situation we can't handle is if we are a 32 bit process and the target
        'process is 64 bit. For that we need to use undocumented NtWow64QueryInformationProcess64 and NtWow64ReadVirtualMemory64 APIs
        Dim Is64BitPeb As Boolean = False
        If Is64BitOperatingSystem() Then
            If Is32BitProcessOn64BitOs(Process.GetCurrentProcess) Then
                If Not Is32BitProcessOn64BitOs(TargetProcess) Then
                    'TODO: Use NtWow64ReadVirtualMemory64 to read from 64 bit processes when we are a 32 bit process instead of throwing this exception
                    Throw New InvalidOperationException("This function cannot be used against a 64 bit process when the calling process is 32 bit")
                End If
            Else
                Is64BitPeb = True
            End If
        End If
        If Is64BitPeb Then
            Return GetCommandLineX64(TargetProcess)
        Else
            Return GetCommandLineX86(TargetProcess)
        End If
    End Function

    Private Shared Function GetCommandLineX64(TargetProcess As Process) As String
        Using MemReader As New MemoryReader(TargetProcess)
            Dim ProcessInfo As New Win32.PROCESS_BASIC_INFORMATION
            'Get basic information about the process, including the PEB address
            Dim Result As Integer = Win32.NtQueryInformationProcess(TargetProcess.Handle, 0, ProcessInfo, Marshal.SizeOf(ProcessInfo), 0)
            If Not Result = 0 Then
                Throw New System.ComponentModel.Win32Exception(Result)
            End If
            Dim ParamPtrBytes(7) As Byte
            'Get a byte array that represents the pointer held in the ProcessParameters member of the PEB structure
            ParamPtrBytes = MemReader.Read(New IntPtr(ProcessInfo.PebBaseAddress.ToInt64 + Win32.PROC_PARAMS_OFFSET_X64), ParamPtrBytes.Length)
            'Convert the byte array to a pointer so that we have the address for the RTL_USER_PROCESS_PARAMETERS structure
            Dim ParamPtr As IntPtr = New IntPtr(BitConverter.ToInt64(ParamPtrBytes, 0))
            Dim UnicodeStringBytes(15) As Byte
            'Read the UNICODE_STRING_64 (16 bytes long) from the start of the CommandLine member of the RTL_USER_PROCESS_PARAMETERS structure
            UnicodeStringBytes = MemReader.Read(New IntPtr(ParamPtr.ToInt64 + Win32.CMDLINE_OFFSET_X64), UnicodeStringBytes.Length)
            'The first 2 bytes in the CommandLine member (UNICODE_STRING_64) tell us the length of the string in bytes
            Dim CmdLineLength As Integer = BitConverter.ToInt16(UnicodeStringBytes, 0)
            If CmdLineLength = 0 Then
                Throw New IO.InvalidDataException("Invalid data read from memory (expected UNICODE_STRING length but found null data)")
            End If
            'Then there's 2 more bytes that just tell us the maximum length, so we ignore them
            'Then there's 4 bytes of padding (not well documented)
            'Then we have the pointer to the actual command line string
            Dim CmdLinePtr As New IntPtr(BitConverter.ToInt64(UnicodeStringBytes, 8))
            'Now that we have the address and length of the string, we can read it into a byte array
            Dim CmdLineBytes() As Byte = MemReader.Read(CmdLinePtr, CmdLineLength)
            MemReader.Close()
            Return Text.Encoding.Unicode.GetString(CmdLineBytes).Trim
        End Using
    End Function

    Private Shared Function GetCommandLineX86(ByVal TargetProcess As Process) As String
        Using MemReader As New MemoryReader(TargetProcess)
            Dim ProcessInfo As New Win32.PROCESS_BASIC_INFORMATION
            'Get basic information about the process, including the PEB address
            Dim Result As Integer = Win32.NtQueryInformationProcess(TargetProcess.Handle, 0, ProcessInfo, Marshal.SizeOf(ProcessInfo), 0)
            If Not Result = 0 Then
                Throw New System.ComponentModel.Win32Exception(Result)
            End If
            Dim ParamPtrBytes(3) As Byte
            'Get a byte array that represents the pointer held in the ProcessParameters member of the PEB structure
            ParamPtrBytes = MemReader.Read(New IntPtr(ProcessInfo.PebBaseAddress.ToInt32 + Win32.PROC_PARAMS_OFFSET_X86), ParamPtrBytes.Length)
            'Convert the byte array to a pointer so that we now have the address for the RTL_USER_PROCESS_PARAMETERS structure
            Dim ParamPtr As IntPtr = New IntPtr(BitConverter.ToInt32(ParamPtrBytes, 0))
            Dim UnicodeStringBytes(7) As Byte
            'Read 8 bytes from the start of the CommandLine member of the RTL_USER_PROCESS_PARAMETERS structure
            UnicodeStringBytes = MemReader.Read(New IntPtr(ParamPtr.ToInt32 + Win32.CMDLINE_OFFSET_X86), UnicodeStringBytes.Length)
            'The first 2 bytes in the CommandLine member tell us the length of the command line string in bytes
            Dim CmdLineLength As Integer = BitConverter.ToInt16(UnicodeStringBytes, 0)
            'The last 4 bytes of the CommandLine member are a pointer to the actual command line string
            Dim CmdLinePtr As New IntPtr(BitConverter.ToInt32(UnicodeStringBytes, 4))
            'Now that we have the address and length of the string, we can read it into a byte array
            Dim CmdLineBytes() As Byte = MemReader.Read(CmdLinePtr, CmdLineLength)
            MemReader.Close()
            Return System.Text.Encoding.Unicode.GetString(CmdLineBytes).Trim
        End Using
    End Function


    Public Class Win32

        Public Const ErrorInsufficientBuffer As UInteger = 122
        Public Const PROC_PARAMS_OFFSET_X86 As Integer = 16
        Public Const PROC_PARAMS_OFFSET_X64 As Integer = 32
        Public Const CMDLINE_OFFSET_X86 As Integer = 64
        Public Const CMDLINE_OFFSET_X64 As Integer = 112

        <StructLayout(LayoutKind.Sequential)> _
        Public Structure PROCESS_BASIC_INFORMATION
            Public ExitStatus As Integer
            Public PebBaseAddress As IntPtr
            Public AffinityMask As IntPtr
            Public BasePriority As Integer
            Public UniqueProcessID As IntPtr
            Public InheritedFromUniqueProcessId As IntPtr
        End Structure

        <Flags()> _
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

        <DllImport("kernel32.dll", EntryPoint:="IsWow64Process", SetLastError:=True)> _
        Public Shared Function IsWow64Process(<InAttribute()> ByVal hProcess As System.IntPtr, <Out()> ByRef Wow64Process As Boolean) As <MarshalAs(UnmanagedType.Bool)> Boolean
        End Function

        <DllImport("kernel32.dll", EntryPoint:="GetModuleHandle", SetLastError:=True)> _
        Public Shared Function GetModuleHandle(ByVal moduleName As String) As IntPtr
        End Function

        <DllImport("kernel32.dll", EntryPoint:="GetProcAddress", SetLastError:=True)> _
        Public Shared Function GetProcAddress(ByVal hModule As IntPtr, ByVal methodName As String) As IntPtr
        End Function

        <DllImport("ntdll.dll", EntryPoint:="NtQueryInformationProcess", SetLastError:=True)> _
        Public Shared Function NtQueryInformationProcess(ByVal handle As IntPtr, ByVal processinformationclass As UInteger, ByRef ProcessInformation As PROCESS_BASIC_INFORMATION,
                                                         ByVal ProcessInformationLength As Integer, ByRef ReturnLength As UInteger) As Integer
        End Function

        <DllImport("kernel32.dll", EntryPoint:="ReadProcessMemory", SetLastError:=True)> _
        Public Shared Function ReadProcessMemory(<InAttribute()> ByVal hProcess As System.IntPtr, <InAttribute()> ByVal lpBaseAddress As IntPtr, <Out()> ByVal lpBuffer As Byte(),
                                                 ByVal nSize As UInteger, <Out()> ByRef lpNumberOfBytesRead As UInteger) As <MarshalAs(UnmanagedType.Bool)> Boolean
        End Function

        <DllImport("Psapi.dll", EntryPoint:="GetModuleFileNameExW", SetLastError:=True)> _
        Public Shared Function GetModuleFileNameExW(ByVal hProcess As IntPtr, ByVal hModule As IntPtr, <MarshalAs(UnmanagedType.LPWStr)> ByVal lpFilename As Text.StringBuilder,
                                                    ByVal nSize As UInteger) As UInteger
        End Function

        <DllImport("kernel32.dll", EntryPoint:="OpenProcess", SetLastError:=True)> _
        Public Shared Function OpenProcess(ByVal dwDesiredAccess As ProcessAccess, <MarshalAs(UnmanagedType.Bool)> ByVal bInheritHandle As Boolean, ByVal dwProcessId As UInteger) As IntPtr
        End Function

        <DllImport("kernel32.dll", EntryPoint:="CloseHandle", SetLastError:=True)> _
        Public Shared Function CloseHandle(<InAttribute()> ByVal Handle As IntPtr) As <MarshalAs(UnmanagedType.Bool)> Boolean
        End Function


    End Class




End Class
