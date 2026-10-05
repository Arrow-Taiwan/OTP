Set sh = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
root = fso.GetParentFolderName(WScript.ScriptFullName)
sh.CurrentDirectory = root
cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File """ & root & "\check.ps1"""
sh.Run cmd, 1, True
