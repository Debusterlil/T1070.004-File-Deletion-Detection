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
