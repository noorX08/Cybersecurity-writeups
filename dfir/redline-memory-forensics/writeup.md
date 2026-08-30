# RedLine — Memory Forensics Write-up

**Lab:** CyberDefenders — RedLine
**Category:** Memory Forensics
**Tools Used:** Volatility 3
**Memory Dump:** MemoryDump.mem

## Scenario
A workstation was flagged for suspicious activity. A memory dump was captured, and the goal was to investigate a possible intrusion, identify the malicious process responsible, and trace related system and network activity.

## Environment Setup
- **OS:** Windows 11
- **Tool:** Volatility 3 (v2.28.0)

---

## Investigation

### Q1 — What is the name of the suspicious process?

**Command:**

C:\Users\NOORJ\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\Scripts\vol.exe -f "C:\Users\NOORJ\Downloads\106-RedLine\temp_extract_dir\MemoryDump.mem"` windows.pstree`

**Finding:** oneetx.exe

| Field | Value |
|---|---|
| PID | 5896 |
| PPID | 8844 |
| Path | Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe |

**Why this is suspicious:**
- **Path** — runs from AppData\Local\Temp, a user-writable temp folder. Legitimate system processes run from System32 or Program Files, not user temp directories — attackers commonly drop payloads here since it's writable without admin rights and easy to clean up afterward.
- **Naming** — oneetx.exe is not a recognized Windows or common application process name.

---

### Q2 — What is the child process name of the suspicious process?

**Command:**

C:\Users\NOORJ\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\Scripts\vol.exe -f "C:\Users\NOORJ\Downloads\106-RedLine\temp_extract_dir\MemoryDump.mem" `windows.pstree`

**Finding:** rundll32.exe

| Field | Value |
|---|---|
| PID | 7732 |
| PPID | 5896 |

**Confirming the relationship:**
rundll32.exe's PPID (5896) matches oneetx.exe's PID (5896) — confirming oneetx.exe launched rundll32.exe directly.

**Why this matters:**
rundll32.exe is a legitimate Windows utility frequently abused by malware to execute malicious DLLs while blending in with normal system activity.

---

### Q3 — What is the memory protection applied to the suspicious process memory region?

**Command:**

C:\Users\NOORJ\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\Scripts\vol.exe -f "C:\Users\NOORJ\Downloads\106-RedLine\temp_extract_dir\MemoryDump.mem" `windows.vadinfo --pid 5896`

**Finding:** PAGE_EXECUTE_READWRITE

**Why this is significant:**
This plugin provides details about the memory regions associated with a process, including their size, attributes, and protections. A region flagged PAGE_EXECUTE_READWRITE is simultaneously writable and executable — a strong indicator of malicious activity (e.g. code injection or shellcode execution), since legitimate processes rarely need memory that can be written to and executed at the same time.

---

### Q4 — What is the name of the process responsible for the VPN connection?

**Command:**

C:\Users\NOORJ\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\Scripts\vol.exe -f "C:\Users\NOORJ\Downloads\106-RedLine\temp_extract_dir\MemoryDump.mem" `windows.pstree`

**Finding:** tun2socks.exe

| Field | Value |
|---|---|
| PID | 4628 |
| PPID | 6724 |
| Path | Program Files (x86)\Outline\resources\app.asar.unpacked\third_party\outline-go-tun2socks\win32\tun2socks.exe |

**Parent chain:** Outline.exe (PID 6724) → explorer.exe

**Conclusion:**
tun2socks.exe is a legitimate component bundled with the Outline VPN client. Its parent chain traces back to explorer.exe, indicating it was manually launched by the user — confirming it is unrelated to the oneetx.exe malicious process chain identified in Q1/Q2.

---

## Key Findings
1. **Malicious process:** oneetx.exe, running from a user-writable temp directory.
2. **Execution technique:** oneetx.exe spawned rundll32.exe — a living-off-the-land technique blending malicious execution with legitimate Windows activity.
3. **Memory evidence:** A PAGE_EXECUTE_READWRITE region tied to oneetx.exe supports the presence of injected or dynamically executed code.
4. **Ruled out:** tun2socks.exe / Outline VPN was investigated and confirmed unrelated to the incident.

## Lessons Learned
This lab reinforced how to trace parent-child process relationships using PID/PPID matching, identify suspicious file paths and memory permissions as indicators of compromise, and recognize when a process is unrelated to the incident rather than assuming everything unfamiliar is malicious.
