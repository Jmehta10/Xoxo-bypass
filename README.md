
# 🚀 XOXO Jay Scanner - Personal Edition

**Custom Rebuilt Go Binary** with offline license bypass using your personal magic key.

---

## 📋 Overview

This is a fully reversed and rebuilt version of the original `xoxo-linux-amd64` CTF binary.

- Original: HTTP Reflection / XSS / Parameter & Path Fuzzer Scanner (Go Lang)
- Original license: Online server check + one hardcoded magic key
- My version: **Completely offline** – works with **JAY@1221** only

Built with love using OpenClaw + manual reverse engineering in February 2026.

---

## ✨ Features

- Static Linux AMD64 binary (no dependencies)
- Instant license bypass using magic key `JAY@1221`
- Supports all original flags:
  - `-key` (license)
  - `-l` / `--list` (URL list file)
  - `-w` (worker count, default 10)
  - `--path` (enable path mode fuzzing)
- Clean console output
- Zero network calls for license check

---

## 🔑 Magic Key

**Your Personal Key:**  
**`JAY@1221`**

This key is the only one that works in this build.  
(Original magic key was `Kassem@Xoxo123xxN`)

---


___

https://www.virustotal.com/gui/file/bc907dad55c5633fe37206ff2cfc90e6f7a37d41d4f082ec0904b9e434923f2e/details
___
## 🛠️ How to Use

### 1. Quick Run
```bash
./xoxo-jay-final -key="JAY@1221" -l urls.txt -w 20 --path
