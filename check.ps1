Add-Type -AssemblyName System.Windows.Forms | Out-Null
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root
$data = Join-Path $root "data"
New-Item -ItemType Directory -Force -Path $data | Out-Null
. (Join-Path $root "lib-totp.ps1")
$lines = New-Object System.Collections.Generic.List[string]
function Add-Line([string]$t) { [void]$lines.Add($t) }
Add-Line ("root=" + $root)
Add-Line ("index.html=" + (Test-Path (Join-Path $root "ui\index.html")))
Add-Line ("app.js=" + (Test-Path (Join-Path $root "ui\app.js")))
Add-Line ("jsQR.js=" + (Test-Path (Join-Path $root "ui\jsQR.js")))
Add-Line ("START.vbs=" + (Test-Path (Join-Path $root "START.vbs")))
$fail = @(Test-TotpRfc6238)
Add-Line ("totp_rfc6238=" + ($(if ($fail.Count -eq 0) { "PASS" } else { "FAIL " + ($fail -join "; ") })))
$ok = (Test-Path (Join-Path $root "ui\index.html")) -and (Test-Path (Join-Path $root "ui\app.js")) -and ($fail.Count -eq 0)
Add-Line ("ok=" + $ok)
$text = [string]::Join("`r`n", $lines)
[System.IO.File]::WriteAllText((Join-Path $data "check.txt"), $text + "`r`n", [System.Text.ASCIIEncoding]::new())
$icon = $(if ($ok) { [System.Windows.Forms.MessageBoxIcon]::Information } else { [System.Windows.Forms.MessageBoxIcon]::Warning })
[System.Windows.Forms.MessageBox]::Show($text, "SCM-OTP CHECK", [System.Windows.Forms.MessageBoxButtons]::OK, $icon) | Out-Null
