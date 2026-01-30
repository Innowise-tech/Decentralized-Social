# Malicious Node.js Loader – Incident Report

## Executive Summary

An obfuscated Node.js script was analyzed and determined to be a **malicious remote code loader**. The script creates a hidden working directory, installs dependencies, contacts an external command-and-control (C2) endpoint, and **executes arbitrary JavaScript received from the server using `eval()`**. This enables full remote code execution on the affected host.

**Severity:** Critical

---

## Scope & Context

* **Language:** Node.js (JavaScript)
* **Obfuscation:** Heavy string table + index shifting
* **Execution Model:** Cross-platform (Windows, Linux, macOS)
* **Threat Class:** Dropper / Loader / Backdoor

---

## Technical Analysis

### 1. Environment Detection

* Uses `os.platform()` to branch behavior for Windows vs Unix-like systems.
* Uses `os.homedir()` to derive a user-writable base path.

### 2. File System Activity

Creates a hidden-looking directory within the user home:

```
~/Programs_X64/
```

Writes a malicious payload file:

```
Programs_X64/main.js
```

### 3. Payload Behavior (`main.js`)

The written payload:

* Imports `axios`
* Sends a POST request to an external domain impersonating a legitimate service
* Adds a custom HTTP header: `x-secret-header: secret`
* Executes server-provided JavaScript dynamically:

  ```js
  eval(response.data)
  ```

This design allows the attacker to fully control victim behavior post-infection.

### 4. Dependency Installation

The loader installs packages silently:

* `axios`
* `sqlite3`

Using:

```
npm init -y
npm install axios sqlite3
```

### 5. Execution & Stealth

**Windows**

* Executes Node.js via PowerShell
* Uses hidden window style

**Linux / macOS**

* Uses background execution via `nohup`
* Redirects output to `app.log`

---

## Network Indicators

### Domains

* `*.whatsapp.app` (non-official, impersonation domain)

### HTTP Characteristics

* Method: POST
* Custom header:

  ```
  x-secret-header: secret
  ```

### Behavior

* Periodic outbound beaconing
* Remote code retrieval and execution

---

## Indicators of Compromise (IOCs)

### File IOCs

```
~/Programs_X64/
~/Programs_X64/main.js
~/Programs_X64/app.log
~/Programs_X64/node_modules/
```

### Process IOCs

* `node` executed in background
* `powershell.exe -WindowStyle Hidden`
* `nohup node main.js`

---

## Detection Rules

### YARA (File-Based)

```yara
rule NodeJS_Remote_Eval_Loader
{
    meta:
        description = "Detects Node.js malware performing remote eval"
        severity = "high"

    strings:
        $eval = "eval(response.data)"
        $axios = "axios.post"
        $npm = "npm install"
        $dir = "Programs_X64"

    condition:
        2 of them
}
```

### Sigma (Windows Process)

```yaml
title: Hidden PowerShell launching Node
level: high
logsource:
  product: windows
  category: process_creation

detection:
  selection:
    ParentImage|endswith: '\\powershell.exe'
    CommandLine|contains:
      - 'WindowStyle Hidden'
      - 'node'
  condition: selection
```

---

## Risk Assessment

| Category              | Risk     |
| --------------------- | -------- |
| Remote Code Execution | Critical |
| Persistence           | Medium   |
| Stealth               | High     |
| Credential Theft      | Possible |

---

## Recommended Response Actions

1. Immediately isolate affected host
2. Remove `Programs_X64` directory
3. Terminate suspicious Node.js processes
4. Block outbound traffic to impersonation domains
5. Rotate credentials used on affected system
6. Perform full malware scan and forensic review

---

## Conclusion

This script represents a **high-risk malware loader** capable of executing attacker-controlled code on demand. Its obfuscation, stealth execution, and remote eval design strongly indicate malicious intent. Immediate remediation and defensive rule deployment are recommended.
