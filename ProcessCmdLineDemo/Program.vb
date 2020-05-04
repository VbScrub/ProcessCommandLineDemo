Module Program

    Sub Main()
        'Example just showing the command line used to launch the current process
        Console.WriteLine(WindowsApi.GetCommandLine(Process.GetCurrentProcess))
        Console.ReadLine()
    End Sub

End Module
