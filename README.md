# router-firmware-cwe-remediation
Static firmware vulnerability audit of TP-Link Archer C7 using Binwalk, uncovering CWE-321, CWE-798, and CWE-1188 flaws with Responder validation and PowerShell/XML remediation.

#Execuetive Summary

# Consumer Router Firmware Audit & CWE Remediation Lab

## Executive Summary
Conducted static firmware analysis on **TP-Link Archer C7 (US) v5 (`1.2.1 Build 20220715`)** inside an isolated VMware lab environment to identify embedded security weaknesses, validate network-layer exposure, and implement configuration and host-level remediations.

---

## 1. Static Firmware Analysis (`Binwalk`)
Extracted the firmware binary using `binwalk -Me` and audited `default-config.xml` alongside the unpacked `squashfs-root` filesystem.

### Key Findings & CWE Mapping

| Finding | Affected Component | Mapped CWE | Severity |
| :--- | :--- | :--- | :--- |
| **Hardcoded Static RSA Private Key** | `default-config.xml` (`<accountmgnt><rsa>`) | **CWE-321:** Use of Hard-coded Cryptographic Key | High |
| **Cleartext Factory Credentials** | `default-config.xml` (`admin:admin`) | **CWE-798:** Use of Hard-coded Credentials | High |
| **Insecure PPTP & NetBIOS Defaults** | `default-config.xml` (`<service name="pptpd">`) | **CWE-1188:** Insecure Default Initialization of Resource | Medium |
| **Passwordless Guest Account** | `etc/shadow` (`guest::...`) | **CWE-258:** Empty Password in Configuration File | Medium |

---

## 2. Broadcast Exposure Validation (`Responder`)
To demonstrate the real-world risk of enabling NetBIOS passthrough (`<netbios_pass>on</netbios_pass>`), an isolated `Host-Only` (`192.168.131.0/24`) virtual segment was configured in VMware.

* **Baseline Test:** Ran `sudo responder -I eth0 -A` (Analyze Mode) in Kali Linux, capturing active unauthenticated **LLMNR** name resolution broadcasts originating from the Windows host (`192.168.131.1`).
* 
* **Risk:** On networks where routers forward NetBIOS/LLMNR broadcasts or where endpoints retain default multicast resolution, attackers on the segment can spoof responses to capture NTLMv2 challenge-response hashes.

---

## 3. Remediation & Verification

### A. Router Firmware Configuration Hardening (`default-config.xml`)
* Disabled unencrypted PPTP access and NetBIOS/Samba broadcast forwarding by default:
  ```xml output via Kali Linux
  <unencrypted_access>off</unencrypted_access>
  <netbios_pass>off</netbios_pass>
  <samba_access>off</samba_access>
  ```
* Removed static RSA private exponent `<d>` and default `admin` credentials in favor of unique per-device key generation and mandatory first-boot password configuration.

### B. Endpoint Hardening & Verification (`PowerShell`)
Disabled Link-Local Multicast Name Resolution (LLMNR) on the Windows host via registry policy:
```powershell command
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type DWord -Value 0
```
* **Post-Remediation Verification:** Re-ran `sudo responder -I eth0 -A` on the isolated segment and confirmed zero LLMNR broadcast leaks occurred.



* **

# SEE Screenshots for more visual details on the findings of the vulnerabilities found on TP Link Firmware
