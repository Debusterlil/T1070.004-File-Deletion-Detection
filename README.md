# MITRE ATT&CK T1070.004 File Deletion Detection PoC

PowerShell-based defensive proof of concept for detecting a sequence where an executable is launched and shortly after deleted.

This repository contains supporting materials for a DFIR research article about **MITRE ATT&CK T1070.004 — File Deletion**.

## Overview

The project demonstrates a simple correlation approach:

1. Sysmon Event ID 1 — Process Creation
2. Sysmon Event ID 26 — File Delete Detected
3. Correlation of the same executable path within a defined time window

Detection condition:

```
ProcessCreate.Image == FileDeleteDetected.TargetFilename
```

and deletion happens within the configured time interval.

## Repository structure

```
detection/
├── Detect-T1070_004.ps1
└── sysmon-t1070.xml
```

## Requirements

- Windows 10/11
- Sysmon
- PowerShell 5+

## Usage

1. Install Sysmon.

2. Apply the provided configuration:

```powershell
sysmon64.exe -c sysmon-t1070.xml
```

3. Run the correlation script:

```powershell
.\Detect-T1070_004.ps1
```

## Example result

```
[ALERT] Executed file deleted shortly after launch

Executable          : C:\Users\dfirlab\Desktop\T1070_004_Test.exe
DeltaSeconds        : 42.999
ProcessCreateRecord : 356
FileDeleteRecord    : 360
```

## Limitations

This project is a laboratory PoC and is not a production SIEM detection rule.

For enterprise environments, similar correlation logic should normally be implemented in SIEM, EDR, or detection engineering pipelines.

## MITRE ATT&CK

Technique:

- T1070.004 — File Deletion

## Safety

The repository contains only defensive detection logic and configuration examples.
No malware, persistence mechanisms, or destructive functionality are included.
