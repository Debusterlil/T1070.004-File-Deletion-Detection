# Windows File Deletion Detection Lab

A DFIR research project focused on detecting **MITRE ATT&CK T1070.004 — File Deletion** activity using Windows telemetry and event correlation.

This repository contains supporting materials for my article published on Xakep.ru:

**Article:**  
[Windows Forensic Recovery — Xakep.ru](https://xakep.ru/2026/08/28/windows-forensic-recovery/)

---

## Research Overview

This project demonstrates a defensive approach to detecting file deletion activity after execution.

The laboratory scenario focuses on correlating Windows telemetry sources to identify suspicious behavior:

- Sysmon Event ID 1 — Process Creation
- Sysmon Event ID 26 — File Delete Detected
- Timeline correlation between execution and deletion events

The goal is to demonstrate how defenders can reconstruct attacker activity using endpoint telemetry.

---

## Repository Structure


detection/
├── Detect-T1070_004.ps1
└── sysmon-t1070.xml


---

## Detection Logic

The detection approach correlates:


ProcessCreate.Image == FileDeleteDetected.TargetFilename


when file deletion occurs within a defined time window after execution.

---

## Requirements

- Windows 10/11
- Sysmon
- PowerShell 5+

---

## Usage

Apply the provided Sysmon configuration:

```powershell
sysmon -c .\detection\sysmon-t1070.xml

Run the detection script:

.\detection\Detect-T1070_004.ps1

Review the correlated events.

Example Detection
[ALERT] Executed file deleted shortly after launch

Executable:
C:\Users\dfirlab\Desktop\T1070_004_Test.exe

DeltaSeconds:
42.999

ProcessCreateRecord:
356

FileDeleteRecord:
360
Limitations

This project is a laboratory proof of concept.

It is not intended to replace enterprise SIEM or EDR detection pipelines.

Production environments should adapt similar correlation logic according to their telemetry architecture.

MITRE ATT&CK

Technique:

T1070.004 — File Deletion
Author

Vitalii (Debusterlil)

Independent DFIR researcher focused on:

Windows Forensics
Threat Detection
Malware Analysis
Reverse Engineering
