# Kavach Antivirus

**Kavach Antivirus v1.0, developed by Cecil Baraik**

Kavach (कवच, "armour") is a real antivirus for Windows 10 and 11, written in C# (.NET 8) with a WPF interface and a Windows Service for always-on protection.

---

## Features

### Scanning
- **Quick scan:** Downloads, Desktop, Documents, Temp, AppData, Startup folders, running programs, startup items and the hosts file
- **Full scan:** every fixed drive
- **Custom scan:** files, folders or USB drives (also by drag and drop)
- **Running programs scan**
- **Right-click "Scan with Kavach"** in Windows Explorer
- **Pause, resume and cancel**, with live progress, file counts and time
- **Scan cache:** unchanged clean files are skipped until signatures change
- **Low CPU mode:** Low / Balanced / Fast scan speed, pause on battery and during full-screen games

### Detection methods
| Method | What it catches |
|---|---|
| SHA-256 hash database | Exact known malware (bundled list + MalwareBazaar downloads) |
| YARA-compatible rule engine | Ransomware, stealers, keyloggers, RATs, miners, Mimikatz, web shells, macro downloaders, Cobalt Strike, EICAR |
| PE heuristics | Packers (UPX, Themida, VMProtect…), encrypted code (entropy), RWX sections, odd entry point, injection / keylogger / credential APIs |
| Script analysis | PowerShell, BAT, VBS, JS, HTA and weaponised `.lnk` shortcuts (encoded commands, download-and-run, AMSI bypass, disabling Defender, deleting shadow copies) |
| Archive scanning | Files inside ZIP, RAR, 7z, TAR, GZ (zip-bomb safe), encrypted archives with programs |
| File-name tricks | Double extensions (`invoice.pdf.exe`), right-to-left override, fake system files (`svchost.exe` outside System32), look-alike names |
| Digital signatures | Authenticode check through Windows `WinVerifyTrust` (fewer false alarms on trusted software) |

Each detection has a level: **Low, Medium, High, Critical**.

### Real-time protection (Windows Service)
- Scans every new or changed file in watched folders the moment it is saved
- **Download warnings** for new programs in Downloads (signed or unsigned)
- **USB auto-scan** plus `autorun.inf` worm blocking
- **Ransomware protection:** hidden bait files plus mass-rename detection; the program writing the most data is killed and quarantined
- **Online rule updates (no account needed):** “Download latest” and a daily automatic check in the service fetch the free [ReversingLabs YARA rules](https://github.com/reversinglabs/reversinglabs-yara-rules) (MIT) from GitHub; Windows rules the engine fully supports are saved as `online_reversinglabs.yar`. MalwareBazaar hashes are optional (needs an abuse.ch Auth-Key)
- **Script memory scanning (fileless attacks):** reads PowerShell Script Block Logging (event 4104) live — scripts are already decoded there, even `-EncodedCommand` ones — checks them with the script analyzer and YARA rules, and stops the PowerShell process if malicious. Test: `tests\script-memory-test\RUN-SCRIPT-MEMORY-TEST.bat`
- **Self-protection:** the service process cannot be terminated or tampered with by normal programs, and auto-restarts if stopped
- Pop-up Windows notifications from the tray icon

### Response
- **Quarantine vault** (AES-256 encrypted), with restore (optionally trust the file) and permanent delete
- **Kill running malware** before removing it
- **Allowlist** of folders, files and trusted SHA-256 fingerprints

### System checks
- Startup items: Run/RunOnce keys (all users), Startup folders, scheduled tasks, auto-start services, Winlogon Shell/Userinit hijacks, IFEO "Debugger" hijacks
- Disable and restore startup items
- Hosts file hijack check, with one-click reset (backup kept)
- Network monitor: live TCP/UDP connections per program, flags known-bad IPs and unsigned programs from Temp/AppData, stop button

### Management
- Scheduled scans (daily or weekly, catch up after the PC was off)
- Signature updates: download MalwareBazaar hashes, import hash lists and YARA files, add single hashes
- Scan history with **PDF / TXT / CSV report export**
- Activity log with filters and export
- VirusTotal lookup (hash only; needs a free API key)
- Settings password, dark and light themes, start with Windows, minimize to tray, run-as-administrator button

---

## Project structure

```
Kavach/
├─ Kavach.sln
├─ build.ps1                     ← builds everything (+ installer if Inno Setup is installed)
├─ signatures/                   ← bundled hash list, IP blacklist, YARA rules
├─ installer/
│  ├─ Kavach.iss                 ← Inno Setup installer script (publisher: Cecil Baraik)
│  ├─ install-service.ps1        ← install the service by hand (testing)
│  └─ uninstall-service.ps1
└─ src/
   ├─ Kavach.Core/               ← the antivirus engine (no UI)
   │  ├─ Engine/                 ← ScanEngine, HashDatabase, RuleEngine (YARA), PeAnalyzer,
   │  │                            ScriptAnalyzer, ArchiveScanner, FileClassifier, SignatureVerifier, ScanCache
   │  ├─ Scanning/               ← ScanJob (threads, pause/resume/cancel), scan locations
   │  ├─ Protection/             ← RealTimeMonitor, RansomwareGuard, UsbMonitor, Scheduler,
   │  │                            SelfProtection, ProtectionHost
   │  ├─ Response/               ← QuarantineManager, ProcessKiller
   │  ├─ SystemChecks/           ← StartupScanner, HostsFileChecker, ProcessScanner, NetworkMonitor
   │  ├─ Infrastructure/         ← settings, logs, history, updates, VirusTotal, reports, named pipe
   │  └─ Native/                 ← Windows API declarations
   ├─ Kavach.App/                ← WPF app (Kavach.exe)
   │  ├─ Themes/                 ← Dark.xaml, Light.xaml, Styles.xaml
   │  ├─ Pages/                  ← Home, Scan, Real-time, System Check, Network, Quarantine,
   │  │                            Allowlist, Updates, History, Activity, Schedules, Preferences, About
   │  └─ Services/               ← tray icon, single instance, dialogs, shared state
   └─ Kavach.Service/            ← Windows Service (KavachService.exe)
```

Data is stored in `C:\ProgramData\Kavach` (settings, quarantine, history, log, signatures).

---

## How to build and run

### You need
- Windows 10 (1809+) or Windows 11, 64-bit
- **Visual Studio 2022** (17.8 or newer) with the **".NET desktop development"** workload. This includes the .NET 8 SDK.

### Run it from Visual Studio
1. Open `Kavach.sln`.
2. Right-click **Kavach.App**, then **Set as Startup Project**.
3. Press **F5**. NuGet packages download automatically on the first build.
4. Kavach opens. Without the service installed, real-time protection runs inside the app while it is open.

To use every feature (quarantining system files, startup items, hosts reset), run Visual Studio **as Administrator**, or use the **Run as administrator** button in Kavach.

### Build the installer (recommended for real use)
1. Install **Inno Setup 6** from https://jrsoftware.org/isinfo.php.
2. Open PowerShell in the `Kavach` folder and run:
   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass
   .\build.ps1
   ```
3. Run `installer\Output\KavachSetup-<version>.exe`.

The installer copies Kavach to `C:\Program Files\Kavach`, registers the **Kavach Antivirus Protection** service (starts with Windows and restarts automatically), and lists the app in Windows **Apps** with publisher **Cecil Baraik**.

### Test that it works
1. Open Kavach, go to **About**, and click **Create EICAR test file**. This is a harmless file that every antivirus detects on purpose.
2. Within a few seconds Kavach shows **"Threat blocked — EICAR-Test-File"** and the file appears in **Quarantine**.
3. Microsoft Defender may catch the file first. That is normal. You can turn off Defender's real-time protection for a moment while testing, or add an exclusion folder in Defender and test there.

Always test real malware samples only inside a virtual machine.

---

## Notes and limits
- Kavach works **alongside** Microsoft Defender; keep Defender on.
- Real-time protection uses file-system notifications, not a kernel driver. It detects a file right after it is written, but it cannot block a file *before* it opens like commercial products with signed kernel drivers can.
- Self-protection stops normal programs from killing the service. A program that already has administrator and debug rights can still get past it, because only kernel drivers can stop that.
- Kavach cannot register as the official antivirus in Windows Security; that requires Microsoft partnership.
- The bundled hash list is small. Press **Signature Updates → Download latest** after installing.

---

© 2026 Cecil Baraik

## Publishing a Kavach update (self-update)

Kavach checks `https://github.com/cecilbaraik19/Kavach/releases` once a day (and from **About Kavach → Check for updates**).

1. Change the version in `Directory.Build.props` (for example `1.2.0`).
2. Run `BUILD-INSTALLER.bat` → `installer\Output\KavachSetup-1.2.0.exe`.
3. On GitHub: repository **Kavach** → **Releases** → **Draft a new release** → tag `v1.2.0` → attach `KavachSetup-1.2.0.exe` → **Publish**.

Every installed Kavach then shows "update available", downloads the installer, checks its SHA-256 against the
fingerprint GitHub reports for the file (a mismatching file is deleted, never run) and starts it with administrator rights.
The update source can be changed in `C:\ProgramData\Kavach\settings.json` (`UpdateRepository`).

