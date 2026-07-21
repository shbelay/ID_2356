# 🛡️ Microsoft Defender XDR (ID 2356) SOC Investigation
## Linux SSH Brute Force → Cryptomining Malware → Persistence → Defense Evasion
## ID 2356 PDF Report: https://www.shbelay.com/files/SOC_Reports/ID_2356.pdf
## Project Overview

This project demonstrates an end-to-end Linux incident investigation performed using **Microsoft Defender XDR** and **Advanced Hunting (KQL)**. The objective was to investigate a multi-stage attack targeting a Linux web server, reconstruct the attack timeline, identify attacker tactics, techniques, and procedures (TTPs), and document the findings in an incident report.

Beginning with a successful SSH compromise, I analyzed authentication logs, process execution, file creation events, malware staging, persistence mechanisms, lateral movement attempts, and Microsoft Defender detections to determine the complete scope of the intrusion.

Throughout the investigation, I correlated endpoint telemetry with external threat intelligence and mapped the attacker's behavior to the MITRE ATT&CK framework using Microsoft XDR.

---

## Scenario

A Linux web server generated alerts indicating suspicious SSH activity followed by privilege escalation and malware execution.

Using Microsoft Defender XDR, I investigated the complete attack lifecycle to determine:

- How the attacker gained initial access
- What reconnaissance was performed
- How malware was staged and executed
- Whether persistence was established
- Whether lateral movement occurred
- Whether cryptocurrency mining was successful
- How Microsoft Defender responded
- What remediation actions should be recommended

---

## Investigation Highlights

- Investigated a successful SSH brute-force attack against a Linux server.
- Identified host reconnaissance targeting GPU hardware for cryptocurrency mining.
- Analyzed malware staging and execution within temporary Linux directories.
- Investigated persistence through cron jobs and SSH authorized keys.
- Examined defense evasion techniques including shell history deletion and artifact cleanup.
- Identified attempted lateral movement against internal hosts.
- Validated malware hashes, domains, and IP addresses using external threat intelligence.
- Confirmed Microsoft Defender detected and terminated the CoinMiner malware before successful mining activity occurred.
- Produced a complete attack timeline and professional SOC investigation report.

---

## Investigation Workflow

1. Investigated SSH authentication logs to identify brute-force activity.
2. Confirmed successful login using compromised credentials.
3. Analyzed attacker reconnaissance targeting GPU hardware.
4. Investigated malware staging and payload delivery.
5. Reviewed shell scripts executed on the compromised host.
6. Identified persistence through cron jobs and SSH authorized keys.
7. Investigated defense evasion and artifact cleanup.
8. Analyzed attempted lateral movement across internal systems.
9. Verified Microsoft Defender detections and malware quarantine actions.
10. Produced a professional SOC investigation report with findings and remediation recommendations.

---

## Tools Used

- Microsoft Defender XDR
- Microsoft Defender for Endpoint
- Advanced Hunting
- Kusto Query Language (KQL)
- VirusTotal
- MITRE ATT&CK Framework

---

## Learning Outcomes

This investigation strengthened my understanding of Linux incident response by following an attacker through every stage of the intrusion—from initial access to malware execution and persistence. It reinforced how attackers leverage legitimate Linux administration tools, shell scripts, cron jobs, SSH authorized keys, and temporary directories to evade detection while establishing cryptomining operations.

The investigation also demonstrated the importance of correlating endpoint telemetry with threat intelligence and validating security controls to determine whether defensive technologies successfully contained the attack.
