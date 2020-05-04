Module Program

    Sub Main()
        'Quick example just showing getting the command line for all currently running processes
        For Each RunningProcess As Process In Process.GetProcesses
            Try
                Dim CommandLine As String = WindowsApi.GetCommandLine(RunningProcess)
                Console.WriteLine(RunningProcess.ProcessName &
                                  Environment.NewLine & CommandLine)
            Catch ex As Exception
                'Will fail with "access denied" error for several processes unless run as admin (even then, there's a couple of system processes you won't be able to access)
                Console.WriteLine("Error getting command line for " & RunningProcess.ProcessName & " : " & ex.Message)
            End Try
            Console.WriteLine()
        Next
        Console.ReadLine()
    End Sub

End Module
