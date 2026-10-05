function ConvertFrom-OtpBase32([string]$Secret) {
  $alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  $s = [regex]::Replace(($Secret + "").ToUpperInvariant(), "[^A-Z2-7]", "")
  $bits = 0
  $value = 0
  $bytes = New-Object System.Collections.Generic.List[byte]
  foreach ($ch in $s.ToCharArray()) {
    $idx = $alpha.IndexOf($ch)
    if ($idx -lt 0) { continue }
    $value = ($value -shl 5) -bor $idx
    $bits += 5
    if ($bits -ge 8) {
      [void]$bytes.Add([byte](($value -shr ($bits - 8)) -band 0xff))
      $bits -= 8
    }
  }
  return [byte[]]$bytes.ToArray()
}

function Get-TotpCode {
  param(
    [string]$Secret,
    [int]$Period = 60,
    [int]$Digits = 6,
    [int64]$Unix = 0
  )
  if ($Period -lt 1) { $Period = 60 }
  if ($Digits -lt 1) { $Digits = 6 }
  if ($Unix -le 0) { $Unix = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }
  $key = ConvertFrom-OtpBase32 $Secret
  if (-not $key -or $key.Length -lt 1) { throw "empty totp key" }
  $counter = [int64][Math]::Floor($Unix / $Period)
  $cb = [BitConverter]::GetBytes([System.Net.IPAddress]::HostToNetworkOrder($counter))
  $hmac = New-Object System.Security.Cryptography.HMACSHA1 @(, $key)
  try { $hash = $hmac.ComputeHash($cb) }
  finally { $hmac.Dispose() }
  $offset = $hash[$hash.Length - 1] -band 0x0f
  $bin = (($hash[$offset] -band 0x7f) -shl 24) -bor ($hash[$offset + 1] -shl 16) -bor ($hash[$offset + 2] -shl 8) -bor $hash[$offset + 3]
  $mod = [int][Math]::Pow(10, $Digits)
  return ($bin % $mod).ToString().PadLeft($Digits, "0")
}

function ConvertFrom-MomoQrText([string]$Raw) {
  $text = ($Raw + "").Trim()
  if ($text.Length -eq 0) { throw "empty qr" }
  $compact = [regex]::Replace($text, "\s+", "")
  $acc = @{
    secret = ""
    period = 60
    digits = 6
    tax = ""
    vendor = ""
    person = ""
    label = "momo OTP"
  }
  if ($compact -match "^otpauth://totp/") {
    $u = [Uri]$compact
    $q = @{}
    $qs = $u.Query.TrimStart("?")
    foreach ($part in $qs.Split("&")) {
      if (-not $part) { continue }
      $i = $part.IndexOf("=")
      $k = [Uri]::UnescapeDataString($(if ($i -lt 0) { $part } else { $part.Substring(0, $i) }))
      $v = [Uri]::UnescapeDataString($(if ($i -lt 0) { "" } else { $part.Substring($i + 1) }))
      if ($k) { $q[$k] = $v }
    }
    $acc.secret = [regex]::Replace((($q["secret"] + "").ToUpperInvariant()), "[^A-Z2-7]", "")
    if ($acc.secret.Length -lt 16) { throw "qr has no secret" }
    $p = 0
    if ([int]::TryParse($q["period"], [ref]$p) -and $p -gt 0) { $acc.period = $p }
    $d = 0
    if ([int]::TryParse($q["digits"], [ref]$d) -and $d -gt 0) { $acc.digits = $d }
    $acc.label = [Uri]::UnescapeDataString($u.AbsolutePath.Trim("/"))
    if (-not $acc.label) { $acc.label = "momo OTP" }
    Merge-OtpLabel $acc $acc.label
    return $acc
  }
  if ($compact.StartsWith("{") -or $compact.StartsWith("[")) {
    $obj = $text | ConvertFrom-Json
    $secret = Find-SecretInObject $obj
    if (-not $secret) { throw "json qr has no secret" }
    $acc.secret = [regex]::Replace($secret.ToUpperInvariant(), "[^A-Z2-7]", "")
    return $acc
  }
  if ($compact -match "^otpauth-migration://") { throw "google authenticator export, not scm bind qr" }
  $b32 = [regex]::Replace($compact.ToUpperInvariant(), "[^A-Z2-7]", "")
  if ($b32.Length -ge 16) {
    $acc.secret = $b32
    return $acc
  }
  throw "not a key qr"
}

function Merge-OtpLabel($acc, [string]$label) {
  $s = ($label + "").Trim()
  if (-not $s) { return }
  $parts = @($s -split "[:/\-_| ]+" | Where-Object { $_ })
  foreach ($p in $parts) {
    if ($p -match "^\d{8}$" -and -not $acc.tax) { $acc.tax = $p }
    elseif ($p -match "^\d{6}$" -and -not $acc.vendor) { $acc.vendor = $p }
  }
}

function Find-SecretInObject($obj) {
  if ($null -eq $obj) { return "" }
  $props = @()
  if ($obj -is [System.Collections.IDictionary]) {
    foreach ($k in @($obj.Keys)) {
      $v = [string]$obj[$k]
      $kn = [string]$k
      if ($kn -match "secret|otpKey|otp_key|totpSecret|sKey|bindKey|otpkey|otpCd|seed") {
        $b32 = [regex]::Replace(($v + "").ToUpperInvariant(), "[^A-Z2-7]", "")
        if ($b32.Length -ge 16) { return $b32 }
      }
      $hit = Find-SecretInObject $obj[$k]
      if ($hit) { return $hit }
    }
    return ""
  }
  try { $props = @($obj.PSObject.Properties) } catch { return "" }
  foreach ($pr in $props) {
    $kn = [string]$pr.Name
    $v = [string]$pr.Value
    if ($kn -match "secret|otpKey|otp_key|totpSecret|sKey|bindKey|otpkey|otpCd|seed") {
      $b32 = [regex]::Replace(($v + "").ToUpperInvariant(), "[^A-Z2-7]", "")
      if ($b32.Length -ge 16) { return $b32 }
    }
    $hit = Find-SecretInObject $pr.Value
    if ($hit) { return $hit }
  }
  return ""
}

function Test-TotpRfc6238 {
  $secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
  $cases = @(
    @{ t = 59; expect = "94287082" },
    @{ t = 1111111109; expect = "07081804" },
    @{ t = 1111111111; expect = "14050471" },
    @{ t = 1234567890; expect = "89005924" },
    @{ t = 2000000000; expect = "69279037" }
  )
  $fail = @()
  foreach ($c in $cases) {
    $got = Get-TotpCode -Secret $secret -Period 30 -Digits 8 -Unix $c.t
    if ($got -ne $c.expect) { $fail += ("t={0} got={1} expect={2}" -f $c.t, $got, $c.expect) }
  }
  return $fail
}
