Set sh = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
root = fso.GetParentFolderName(WScript.ScriptFullName)
sh.CurrentDirectory = root
If Not fso.FolderExists(root & "\data") Then fso.CreateFolder root & "\data"
marker = root & "\data\ps-ran.txt"
urlf = root & "\data\url.txt"
If fso.FileExists(marker) Then fso.DeleteFile marker, True
If fso.FileExists(urlf) Then fso.DeleteFile urlf, True
cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File """ & root & "\start.ps1"""
rc = sh.Run(cmd, 1, True)
If Not fso.FileExists(urlf) Then
  extra = " rc=" & rc
  errf = root & "\data\launch-err.txt"
  logf = root & "\data\boot-log.txt"
  If fso.FileExists(errf) Then extra = extra & vbCrLf & fso.OpenTextFile(errf, 1, False).ReadAll
  If fso.FileExists(logf) Then extra = extra & vbCrLf & fso.OpenTextFile(logf, 1, False).ReadAll
  MsgBox "SCM-OTP did not stay running." & extra, 16, "SCM-OTP"
End If
