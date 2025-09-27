# 🎯 Threat Advisory – Webflow Browser Dropper Campaign (September 2025)

## 📌 Summary

This advisory describes a phishing campaign that abused **legitimate infrastructure**, including a **compromised business email account** and **Webflow/Wix-hosted websites**,  to distribute a stealthy **malware dropper**. The payload abused Microsoft Edge’s command-line flags to bypass user interaction and execute silently, dropping secondary payloads and establishing persistence.

---

## 📥 Delivery Mechanism

- **Sender Address (Compromised):** `[redacted]@peacockpress.net`
- **Authenticated Sender:** `[redacted]@peacockpress.net`
- **Mail Server:** `smtp6.relay.iad3b.emailsrvr.com` → (Rackspace Emailsrvr infrastructure)  
- **Phish Format:** HTML email with no visible attachment
- **Phishing Links (defanged):**  
    - hxxps://myastound[.]webflow[.]io → impersonated browser update page  
    - hxxps://anisholi406[.]wixsite[.]com/my-site-2 → second-stage malware delivery  

The email was delivered via **authenticated SMTP**, indicating either a credential compromise or abuse of the mail server by an insider. The phishing page was hosted on **Webflow.io**, a legitimate web development platform.

---

## 🔬 Payload Behavior

- The landing page served a fake browser update interface.
- Upon interaction, the dropper executed silently using:

msedge.exe --simulate-outdated-no-au


- **Unpacked files** were written to:
C:\Program Files\chrome_Unpacker_BeginUnzipping5728_*


- The payload used **WriteProcessMemory** and **CreateRemoteThread** for injection.
- Registry keys were written for **persistence** and **telemetry control**.

---

## 📎 Indicators of Compromise (IOCs)

### Malicious URLs / Domains:
- `https://myastound.webflow.io`
- `https://anisholi406.wixsite.com`

### IP Addresses:
- `104.18.36.248`
- `146.20.161.107`

### SHA256 File Hashes:
- `5f63beaaefa8bfa3a5564e970ab0b831cdcb0999b6c07f3c748f6674d005bc51`
- `e873620645d6cfc6c5403a927609d6337aec31c0577e8c9248758b8cac582538`
- `0dfc1b8fbfd759da0a7ddaabd296168a5e741149775594696b16434a0c612551`

### Registry Keys (Persistence):
- `\REGISTRY\USER\S-1-5-19\Software\Microsoft\Cryptography\TPM\Telemetry`
- `\REGISTRY\MACHINE\Software\Classes\...\Deployment\Package\...\{GUID}`

### File Paths Observed:
- `C:\Program Files\chrome_Unpacker_BeginUnzipping5728_*`

### Email IOCs:
- **From:** `[redacted]@peacockpress.net`
- **Authenticated Sender:** `[redacted]@peacockpress.net`
- **SMTP IP:** `146.20.161.107`
- **Email Auth:** `ESMTPSA (authenticated)`
- **MIME-Type:** `multipart/related`
- **Headers:** `X-MS-Has-Attach: yes` *(HTML email, no visible attachment)*

---

## 🧪 YARA Rule

```yara
rule Webflow_BrowserDropper_Sept2025
{
  meta:
      triage_description = "Detects browser dropper delivered via Webflow phishing"
      triage_score = 85
      author = "YourHandle"
      date = "2025-09-25"
      family = "Unknown"
      campaign = "Webflow-Phish-Sep2025"

  strings:
      $cmd1 = "--simulate-outdated-no-au" wide ascii
      $path1 = "chrome_Unpacker_BeginUnzipping" ascii
      $reg1 = "Microsoft\\Cryptography\\TPM\\Telemetry" ascii
      $pipe = "\\\\.\\pipe\\" ascii
      $edge_exe = "msedge.exe" ascii

  condition:
      (uint16(0) == 0x5A4D) and 3 of ($cmd1, $path1, $reg1, $pipe, $edge_exe)
}
```
Disclaimer: This YARA rule is provided for research and detection purposes only.  
It may generate false positives. Validate before production deployment.  

---

## 🛡️ Mitigation Recommendations

- Block all domains and IPs listed in this report.
- Add hashes to your EDR and SIEM blocklists.
- Enable alerting for unusual Edge flags or child processes.
- Apply MFA to all business email accounts.
- Notify Webflow and affected email provider (RCN/PeacockPress).

### 📚 References & Credits

- [VT Collection: View VirusTotal IOC Collection](https://www.virustotal.com/gui/collection/e60373b16c25114cbc01c6f0b034d0cbfa8bf8f01c939d87ff13f3d1d6d73a39/summary)
- [VT Graph: Open Interactive Graph](https://www.virustotal.com/graph/g7e3be92915be41928f5853199de88cea157337c3bb9a43199777bf47170a35c4)
- [Hatching Triage behavioral analysis](https://tria.ge/250924-pnn3xsxwes)
- Header review via internal investigation

---

### **Author: Jonathan DeLeon / SaberGuard**
### **Date: September 26, 2025**
### **License: MIT**
