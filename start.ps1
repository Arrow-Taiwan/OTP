$ErrorActionPreference = "Continue"
$here = $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($here)) { $root = (Get-Location).Path } else { $root = Split-Path -Parent $here }
Set-Location -LiteralPath $root
$data = Join-Path $root "data"
$ui = Join-Path $root "docs"
if (-not (Test-Path -LiteralPath $ui)) { $ui = Join-Path $root "ui" }
New-Item -ItemType Directory -Force -Path $data, $ui | Out-Null
$log = Join-Path $data "boot-log.txt"
function Log([string]$t) {
  $line = (Get-Date).ToString("s") + " " + $t
  [System.IO.File]::AppendAllText($log, $line + "`r`n", [System.Text.ASCIIEncoding]::new())
}
[System.IO.File]::WriteAllText($log, "", [System.Text.ASCIIEncoding]::new())
Log "begin root=$root"
[System.IO.File]::WriteAllText((Join-Path $data "ps-ran.txt"), ((Get-Date).ToString("s") + " root=" + $root), [System.Text.ASCIIEncoding]::new())
Log "marker written"

function Show-Err([string]$text) {
  Log ("ERR " + $text)
  [System.IO.File]::WriteAllText((Join-Path $data "launch-err.txt"), $text, [System.Text.UTF8Encoding]::new($true))
  try {
    Add-Type -AssemblyName System.Windows.Forms | Out-Null
    [System.Windows.Forms.MessageBox]::Show($text, "SCM-OTP", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
  } catch {
    Read-Host "Error. Press Enter"
  }
}

try {
  . (Join-Path $root "lib-totp.ps1")
  Log "lib-totp ok"
} catch {
  Show-Err ("lib-totp: " + $_.Exception.Message)
  exit 1
}

$jsqrDst = Join-Path $ui "jsQR.js"
$parent = Split-Path $root -Parent
foreach ($p in @(
  (Join-Path $parent "BeiYi-NanZu-SCM\ui\jsQR.js"),
  (Join-Path $ui "jsQR.js")
)) {
  if ((Test-Path -LiteralPath $p) -and ((Get-Item -LiteralPath $p).Length -gt 10000)) {
    if ($p -ne $jsqrDst) { Copy-Item -LiteralPath $p -Destination $jsqrDst -Force }
    Log "jsQR ready"
    break
  }
}

$cfgPath = Join-Path $data "config.json"
$bind = "127.0.0.1"
$portWant = 18780
if (Test-Path -LiteralPath $cfgPath) {
  try {
    $cfg = Get-Content -LiteralPath $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($cfg.bind) { $bind = [string]$cfg.bind }
    if ($cfg.port) { $portWant = [int]$cfg.port }
  } catch { Log "config parse skip" }
}
$accPath = Join-Path $data "accounts.json"
if (-not (Test-Path -LiteralPath $accPath)) {
  [System.IO.File]::WriteAllText($accPath, "{`"selected`":`"`",`"accounts`":[]}", [System.Text.ASCIIEncoding]::new())
}

function Get-Accounts {
  try {
    $j = Get-Content -LiteralPath $accPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $j.accounts) { $j | Add-Member -NotePropertyName accounts -NotePropertyValue @() -Force }
    return $j
  } catch {
    return [pscustomobject]@{ selected = ""; accounts = @() }
  }
}
function Save-Accounts($obj) {
  [System.IO.File]::WriteAllText($accPath, ($obj | ConvertTo-Json -Depth 8), [System.Text.UTF8Encoding]::new($true))
}

function Write-Res($res, [int]$code, [string]$type, [byte[]]$bytes) {
  if (-not $bytes) { $bytes = [byte[]]@() }
  $res.StatusCode = $code
  $res.ContentType = $type
  $res.ContentLength64 = $bytes.Length
  if ($bytes.Length -gt 0) { $res.OutputStream.Write($bytes, 0, $bytes.Length) }
  $res.Close()
}

function Handle-Req($req, $res) {
  $path = [Uri]::UnescapeDataString($req.Url.AbsolutePath)
  $method = $req.HttpMethod.ToUpperInvariant()
  if ($method -eq "OPTIONS") { Write-Res $res 200 "text/plain" ([byte[]]@()); return }
  if ($path -eq "/api/accounts" -and $method -eq "GET") {
    Write-Res $res 200 "application/json; charset=utf-8" ([Text.Encoding]::UTF8.GetBytes(((Get-Accounts) | ConvertTo-Json -Depth 8)))
    return
  }
  if ($path -eq "/api/accounts" -and $method -eq "POST") {
    try {
      $sr = New-Object IO.StreamReader($req.InputStream, [Text.Encoding]::UTF8)
      $rawBody = $sr.ReadToEnd()
      $sr.Close()
      $body = $rawBody | ConvertFrom-Json
      $pack = Get-Accounts
      $list = @($pack.accounts)
      $id = [string]$body.id
      if (-not $id) { $id = [guid]::NewGuid().ToString("N").Substring(0, 12) }
      $secret = ""
      $period = 60
      $digits = 6
      if ($body.raw) {
        $parsed = ConvertFrom-MomoQrText ([string]$body.raw)
        $secret = $parsed.secret
        $period = $parsed.period
        $digits = $parsed.digits
        if (-not $body.tax -and $parsed.tax) { $body | Add-Member tax $parsed.tax -Force }
        if (-not $body.vendor -and $parsed.vendor) { $body | Add-Member vendor $parsed.vendor -Force }
        if (-not $body.person -and $parsed.person) { $body | Add-Member person $parsed.person -Force }
      } else {
        $secret = [regex]::Replace((($body.secret + "").ToUpperInvariant()), "[^A-Z2-7]", "")
        if ($body.period) { $period = [int]$body.period }
        if ($body.digits) { $digits = [int]$body.digits }
      }
      if ($secret.Length -lt 16) { throw "need SCM bind QR image" }
      $row = [pscustomobject]@{
        id = $id; secret = $secret; period = $period; digits = $digits
        tax = [string]$body.tax; vendor = [string]$body.vendor; person = [string]$body.person
      }
      $found = $false
      $next = @()
      foreach ($a in $list) {
        if ([string]$a.id -eq $id) { $next += $row; $found = $true } else { $next += $a }
      }
      if (-not $found) { $next += $row }
      $pack.accounts = $next
      $pack.selected = $id
      Save-Accounts $pack
      Write-Res $res 200 "application/json; charset=utf-8" ([Text.Encoding]::UTF8.GetBytes((@{ ok = $true; id = $id } | ConvertTo-Json)))
    } catch {
      Write-Res $res 200 "application/json; charset=utf-8" ([Text.Encoding]::UTF8.GetBytes((@{ ok = $false; message = $_.Exception.Message } | ConvertTo-Json)))
    }
    return
  }
  if ($path -eq "/api/delete" -and $method -eq "POST") {
    $sr = New-Object IO.StreamReader($req.InputStream, [Text.Encoding]::UTF8)
    $body = $sr.ReadToEnd() | ConvertFrom-Json
    $sr.Close()
    $pack = Get-Accounts
    $id = [string]$body.id
    $pack.accounts = @($pack.accounts | Where-Object { [string]$_.id -ne $id })
    if ([string]$pack.selected -eq $id) {
      $pack.selected = $(if ($pack.accounts.Count -gt 0) { [string]$pack.accounts[0].id } else { "" })
    }
    Save-Accounts $pack
    Write-Res $res 200 "application/json; charset=utf-8" ([Text.Encoding]::UTF8.GetBytes((@{ ok = $true } | ConvertTo-Json)))
    return
  }
  if ($path -eq "/api/select" -and $method -eq "POST") {
    $sr = New-Object IO.StreamReader($req.InputStream, [Text.Encoding]::UTF8)
    $body = $sr.ReadToEnd() | ConvertFrom-Json
    $sr.Close()
    $pack = Get-Accounts
    $pack.selected = [string]$body.id
    Save-Accounts $pack
    Write-Res $res 200 "application/json; charset=utf-8" ([Text.Encoding]::UTF8.GetBytes((@{ ok = $true } | ConvertTo-Json)))
    return
  }
  if ($path -eq "/api/selftest" -and $method -eq "GET") {
    $fail = @(Test-TotpRfc6238)
    Write-Res $res 200 "application/json; charset=utf-8" ([Text.Encoding]::UTF8.GetBytes((@{ ok = ($fail.Count -eq 0); fail = $fail } | ConvertTo-Json)))
    return
  }
  $name = $path.TrimStart("/").Replace("/", [IO.Path]::DirectorySeparatorChar)
  if (-not $name) { $name = "index.html" }
  if ($name.Contains("..")) { Write-Res $res 400 "text/plain" ([byte[]]@()); return }
  $full = [IO.Path]::GetFullPath((Join-Path $ui $name))
  $rootUi = [IO.Path]::GetFullPath($ui)
  if (-not $full.StartsWith($rootUi, [StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $full)) {
    Write-Res $res 404 "text/plain" ([Text.Encoding]::UTF8.GetBytes("404"))
    return
  }
  $ext = [IO.Path]::GetExtension($full).ToLowerInvariant()
  $type = "application/octet-stream"
  if ($ext -eq ".html") { $type = "text/html; charset=utf-8" }
  if ($ext -eq ".js") { $type = "text/javascript; charset=utf-8" }
  if ($ext -eq ".css") { $type = "text/css; charset=utf-8" }
  Write-Res $res 200 $type ([IO.File]::ReadAllBytes($full))
}

function Find-Chrome {
  $pf = [Environment]::GetFolderPath("ProgramFiles")
  $local = [Environment]::GetFolderPath("LocalApplicationData")
  $pfx86 = [Environment]::GetEnvironmentVariable("ProgramFiles(x86)")
  $list = @(
    (Join-Path $local "Google\Chrome\Application\chrome.exe"),
    (Join-Path $pf "Google\Chrome\Application\chrome.exe")
  )
  if ($pfx86) { $list += (Join-Path $pfx86 "Google\Chrome\Application\chrome.exe") }
  foreach ($p in $list) {
    if ($p -and (Test-Path -LiteralPath $p)) { return $p }
  }
  return $null
}

$listener = $null
$port = $null
try {
  foreach ($p in $portWant..($portWant + 20)) {
    $L = New-Object System.Net.HttpListener
    $prefix = "http://" + $bind + ":" + $p + "/"
    try {
      $L.Prefixes.Add($prefix)
      $L.Start()
      $listener = $L
      $port = $p
      Log "listen $prefix"
      break
    } catch {
      Log ("port $p fail " + $_.Exception.Message)
      try { $L.Close() } catch {}
    }
  }
  if (-not $listener) { throw "HttpListener start failed" }

  $url = "http://127.0.0.1:$port/"
  [System.IO.File]::WriteAllText((Join-Path $data "url.txt"), $url, [System.Text.ASCIIEncoding]::new())
  Log "url $url"

  $chrome = Find-Chrome
  Log ("chrome=" + $chrome)
  if ($chrome) {
    Start-Process -FilePath $chrome -ArgumentList @("--new-window", $url) | Out-Null
  } else {
    Start-Process $url | Out-Null
  }
  Log "browser opened; serving"

  while ($listener.IsListening) {
    $ctx = $null
    try { $ctx = $listener.GetContext() } catch { break }
    if ($null -eq $ctx) { continue }
    try { Handle-Req $ctx.Request $ctx.Response } catch {
      Log ("req " + $_.Exception.Message)
      try { Write-Res $ctx.Response 500 "text/plain" ([Text.Encoding]::UTF8.GetBytes($_.Exception.Message)) } catch {}
    }
  }
} catch {
  Show-Err $_.Exception.ToString()
  exit 1
}
