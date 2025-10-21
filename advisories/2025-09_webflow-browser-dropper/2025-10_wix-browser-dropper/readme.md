# 🎯 Threat Advisory – RCN / Astound Impersonation (October 2025)

## 📌 Summary
This advisory documents a phishing site impersonating **RCN (Astound Broadband)** and hosted on **Wix** infrastructure. Sandbox analysis of the landing page shows browser/environment enumeration, registry modification, and suspicious inter-process memory writes consistent with **credential harvesting** workflows and potential **browser-based dropper** activity.

**Primary phishing URL (defanged):**  
hxxps://contact154942[.]wixsite[.]com/myrcn

**Legit infrastructure abused (observed in session):**  
`static.wixstatic.com`, `static.parastorage.com`, `siteassets.parastorage.com`, `frog.wix.com`, `panorama.wixapps.net`

---

## 📥 Delivery Mechanism
- **Lure:** RCN-branded login/portal page (Wix-hosted).
- **Goal:** Harvest credentials; possible follow-on payload delivery via browser components.
- **Notes:** The page loads numerous Wix/CDN scripts and assets; telemetry endpoints (`frog.wix.com`, `panorama.wixapps.net`) were observed as part of standard Wix operations but appear leveraged by the actor’s cloned site.

---

## 🔬 Payload / Behavioral Highlights
- **Browser & System Discovery:**  
  - Browser info enumeration (T1217)  
  - System info / registry queries under `HARDWARE\DESCRIPTION\System\BIOS` (T1082, T1012)
- **Registry Modification:**  
  - Writes to `HKU\S-1-5-19\Software\Microsoft\Cryptography\TPM\Telemetry` (T1112)
- **Process Activity (Edge 133):**  
  - Multiple `msedge.exe` utility/renderer/gpu helper processes  
  - High count of **WriteProcessMemory** events to sibling Edge processes (T1055 - injection technique indicators)  
  - Uses `FindShellTrayWindow` / `SendNotifyMessage` in suspicious patterns
- **Temp/Unpacker Artifacts:**  
  - `C:\Windows\SystemTemp\chrome_Unpacker_BeginUnzipping5508_*` with small manifests and data buffers (typical of browser “update”/extension unpack flows abused by droppers)

**Environment:** Windows 11 21H2 x64 | Edge 133.0.3065.69  
**Sandbox score:** 4 / 10 (behavioral indicators present; not all malicious stages triggered)

---

## 📎 Indicators of Compromise (IOCs)

### Malicious URL / Domains
- hxxps://contact154942[.]wixsite[.]com/myrcn
- Associated CDN/infra observed during session (legit but abused by phish):
  - static[.]wixstatic[.]com  
  - static[.]parastorage[.]com  
  - siteassets[.]parastorage[.]com  
  - frog[.]wix[.]com  
  - panorama[.]wixapps[.]net

### File Paths Observed
- `C:\Windows\SystemTemp\chrome_Unpacker_BeginUnzipping5508_*\*`
- `C:\Users\Admin\AppData\Local\Microsoft\Edge\User Data\Crashpad\settings.dat`

### SHA256 Hashes (samples from session)
- `18b607590878ac242947e9544e602d9d438953529a7a6625bcfac5347bf5fee3` (Crashpad settings.dat)
- `62f8e0aa77767ecc42974c5fa6197b47f5569aaca565706c78cac43e262c72e2` (data.txt in SystemTemp unpacker dir)
- `934c260823e8c847c01e1538d8fd2d9c1a7847ba8841bb1ab06446b90ca63d15` (manifest.json in SystemTemp unpacker dir)

### Registry Keys (Discovery / Telemetry / Class Reg)
- `\REGISTRY\MACHINE\HARDWARE\DESCRIPTION\System\BIOS\SystemProductName`
- `\REGISTRY\MACHINE\HARDWARE\DESCRIPTION\System\BIOS\SystemManufacturer`
- `\REGISTRY\USER\S-1-5-19\Software\Microsoft\Cryptography\TPM\Telemetry`
- Class/Instance keys created under `HKLM\SOFTWARE\Classes\CLSID\{1f3427c8-5c10-4210-aa03-2ee45287d668}\Instance\`  
- AppModel deployment-related key creation under Local Settings (Edge app context)

---

## 🧪 YARA Rule
> Detects artifacts/behaviors common to this campaign (browser “update”/unpacker flow + Edge-centric strings).  
> **Note:** For **file** scanning (PE), tune paths/strings to your environment. Validate in a test tier before production.

```yara
rule RCN_Astound_Impersonation_Oct2025
{
  meta:
    triage_description = "Detects browser-dropper style unpacker + Edge strings linked to RCN/Astound phish"
    triage_score       = 80
    author             = "SaberGuard CTI"
    date               = "2025-10-20"
    family             = "Unknown"
    campaign           = "RCN-Astound-Phish-Oct2025"

  strings:
    $edge     = "msedge.exe" ascii
    $unpack   = "chrome_Unpacker_BeginUnzipping" ascii
    $tele     = "Microsoft\\Cryptography\\TPM\\Telemetry" ascii
    $flag     = "--simulate-outdated-no-au" ascii wide
    $pipe     = "\\\\.\\pipe\\" ascii
    $wpm      = "WriteProcessMemory" ascii

  condition:
    3 of ($edge, $unpack, $tele, $flag, $pipe, $wpm)
}
