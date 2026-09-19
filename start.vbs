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
    Quote(fileSystem.BuildPath(scriptDirectory, "run.ps1"))

' Window style 0 keeps both this launcher and PowerShell hidden. Waiting for
' run.ps1 lets us report startup failures without leaving a console open.
exitCode = shell.Run(command, 0, True)
If exitCode <> 0 Then
    MsgBox "Service startup failed. Run run.ps1 -Foreground for details.", _
        vbCritical, "Codex Account Tool"
End If
WScript.Quit exitCode

Function Quote(value)
    Quote = Chr(34) & value & Chr(34)
End Function
