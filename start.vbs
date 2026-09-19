Option Explicit

Dim fileSystem, shell, scriptDirectory, powershellPath, command, exitCode

Set fileSystem = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")

scriptDirectory = fileSystem.GetParentFolderName(WScript.ScriptFullName)
powershellPath = shell.ExpandEnvironmentStrings("%SystemRoot%") & _
    "\System32\WindowsPowerShell\v1.0\powershell.exe"

If Not fileSystem.FileExists(powershellPath) Then
    powershellPath = "powershell.exe"
End If

command = Quote(powershellPath) & _
    " -NoLogo -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File " & _
    Quote(fileSystem.BuildPath(scriptDirectory, "run.ps1")) & " -Launch"

' The helper stays hidden. It opens the service console only on the first run;
' later runs signal that existing console to restart its child service.
exitCode = shell.Run(command, 0, True)
If exitCode <> 0 Then
    MsgBox "Service startup failed. Run run.ps1 -Foreground for details.", _
        vbCritical, "Codex Account Tool"
End If
WScript.Quit exitCode

Function Quote(value)
    Quote = Chr(34) & value & Chr(34)
End Function
