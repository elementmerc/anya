/**
 * Static descriptions for known suspicious / noteworthy Windows APIs.
 * Used in the Imports tab to explain why a function is flagged.
 */
export const API_DESCRIPTIONS: Record<string, string> = {
  // ── Tier 1: Injection / persistence / exfil ──
  CreateRemoteThread:
    "Creates a thread in a remote process — the primary mechanism for classic DLL injection and shellcode injection.",
  WriteProcessMemory:
    "Writes memory to another process — used to plant shellcode or overwrite code in a target process.",
  VirtualAllocEx:
    "Allocates executable memory in a remote process — prerequisite for injection payloads.",
  NtQueueApcThread:
    "Queues an Asynchronous Procedure Call in a remote thread — used for APC injection (stealth shellcode execution).",
  QueueUserAPC:
    "Win32 wrapper for APC injection — stealthier than CreateRemoteThread, bypasses some EDR heuristics.",
  RtlCreateUserThread:
    "Undocumented NTDLL routine to create a thread in another process — used to evade API-level hooks.",
  NtCreateThreadEx:
    "Lower-level thread creation in a remote process — bypasses some CreateRemoteThread detection.",
  NtMapViewOfSection:
    "Maps a section (shared memory) into a target process — used for process hollowing and mapping injections.",
  SetWindowsHookEx:
    "Installs a system-wide hook — used for keylogging (WH_KEYBOARD) and legacy DLL injection (WH_CBT).",
  SetWindowsHookExA:
    "ANSI variant of SetWindowsHookEx — same risk profile.",
  SetWindowsHookExW:
    "Unicode variant of SetWindowsHookEx — same risk profile.",
  NtQueryInformationProcess:
    "Queries internal process structures — the standard technique to detect debuggers via the PEB BeingDebugged flag.",
  ZwSetInformationThread:
    "Sets thread information class — used to hide threads from debuggers (ThreadHideFromDebugger).",
  NtSetInformationThread:
    "NT-level alias of ZwSetInformationThread — same anti-debug use.",
  RegSetValueEx:
    "Writes a registry value — used for Run/RunOnce persistence keys, service configuration, and COM hijacking.",
  RegCreateKeyEx:
    "Creates or opens a registry key — frequently precedes RegSetValueEx for persistence setup.",
  CreateService:
    "Creates a Windows service — grants high-privilege persistence that survives reboots.",
  StartService:
    "Starts a Windows service — typically follows CreateService to activate a planted persistent service.",
  InternetOpen:
    "Opens a WinINet internet session — baseline indicator of outbound network communication.",
  InternetOpenUrl:
    "Opens a URL over HTTP/HTTPS/FTP — direct remote resource access without browser mediation.",
  URLDownloadToFile:
    "Downloads a file from a URL to disk — classic dropper / downloader behaviour.",
  WinHttpOpen:
    "Opens a WinHTTP session — alternative to WinINet for HTTP communication, popular in backdoors.",
  GetAsyncKeyState:
    "Reads the instantaneous state of a key — core keylogger API, monitors keystrokes across all windows.",

  // ── Tier 2: Noteworthy / dual-use ──
  OpenProcess:
    "Opens a handle to another process — legitimate for monitoring tools, but required for all process injection techniques.",
  OpenProcessToken:
    "Opens a process's access token — used for privilege escalation via token manipulation.",
  AdjustTokenPrivileges:
    "Modifies the privileges of an access token — used to enable SeDebugPrivilege for cross-process access.",
  IsDebuggerPresent:
    "Checks the PEB BeingDebugged flag — the simplest anti-debug check; present in many legitimate apps too.",
  CheckRemoteDebuggerPresent:
    "Checks if a remote debugger is attached — stronger anti-debug signal than IsDebuggerPresent.",
  OutputDebugString:
    "Sends a string to the debugger — can be used as a timing oracle to detect debugging.",
  OutputDebugStringA:
    "ANSI variant of OutputDebugString.",
  OutputDebugStringW:
    "Unicode variant of OutputDebugString.",
  DebugBreak:
    "Triggers a breakpoint exception — used in anti-debug code to crash or misbehave under a debugger.",
  CreateToolhelp32Snapshot:
    "Snapshots running processes, threads, or modules — used by legitimate tools and also by malware to enumerate targets.",
  WSAStartup:
    "Initialises Winsock — any binary calling this intends to use network sockets.",
  socket:
    "Creates a network socket — raw socket communication.",
  connect:
    "Connects a socket to a remote address — indicates outbound C2 or exfiltration connectivity.",
  CryptEncrypt:
    "Encrypts data via CryptoAPI — used for payload protection or data exfiltration obfuscation.",
  CryptDecrypt:
    "Decrypts data via CryptoAPI — may decrypt embedded payload.",
  CryptAcquireContext:
    "Acquires a CSP handle — prerequisite for most CryptoAPI operations.",
  DeleteFile:
    "Deletes a file — used for anti-forensics, payload cleanup after execution.",
  MoveFile:
    "Moves or renames a file — used to relocate dropped payloads.",
  CopyFile:
    "Copies a file — used to spread or stage payloads.",
};

/** Returns the description for a given API name, or undefined if unknown. */
export function getApiDescription(name: string): string | undefined {
  return API_DESCRIPTIONS[name] ?? API_DESCRIPTIONS[name + "A"] ?? API_DESCRIPTIONS[name + "W"];
}
