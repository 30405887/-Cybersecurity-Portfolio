#  Cybersecurity Portfolio  
## Investigating Red Stealer — Threat Intelligence & Malware Analysis (SOC Lab)

---

###  Summary  
This project documents a hands-on investigation into a suspicious executable suspected of communicating with a Command & Control (C2) server. Using CyberDefenders-style threat intelligence tools like VirusTotal and MalwareBazaar, I performed both static and dynamic analysis to uncover Indicators of Compromise (IOCs), identify malware family aliases, and map observed behaviors to MITRE ATT&CK techniques.

The sample (SHA256: `248FCC901AFF4E4B4C48C91E4D78A939BF681C9A1BC24ADDC3551B32768F907B`) was classified as a trojan/information stealer from the RedLine or RecordStealer family. It appeared under filenames such as `Wextract.EXE`, `malicious.exe`, and `red.exe`. Analysis revealed a first-seen timestamp of `2023-10-06 04:41:50 UTC`, a decoded C2 IP of `77.91.124.55` over port `1971`, and evidence of local data harvesting (`MITRE T1005`). Static inspection showed use of `ADVAPI32.dll` for privilege escalation attempts.

The final report includes methodology, key findings, IOC tables, detection rules (YARA/Sigma), and remediation strategies for SOC and Incident Response teams. This exercise reinforced NIST CSF functions—Identify, Detect, Respond—and aligned with unit learning outcomes.

---

###  Introduction  
- **Platform chosen for portfolio**: GitHub  
- **Portfolio link**: `30405887/cyber-portfolio-Bernie-Ybanez-30405887`  
- **Hands-on platform used**: CyberDefenders (Lab: Red Stealer)  
- **Why selected**: Simulates a real-world SOC threat intel workflow—analyzing a suspicious binary/hash, extracting IOCs, identifying C2 infrastructure, and producing operational guidance for IR. Complements course outcomes in incident response, threat intelligence, and forensics.

---

###  Problem / Challenge  
A suspicious executable was discovered on an endpoint and suspected to be part of a C2-enabled information-stealer campaign. As a Threat Intelligence analyst in the SOC, my task was to analyze the hash, identify malware family and IOCs, determine C2 endpoints, map behaviors to MITRE ATT&CK, and produce actionable items for SOC and IR teams.

---

###  Project Goals  
- Use VirusTotal and MalwareBazaar to classify the sample and gather metadata  
- Perform safe static analysis (hashing, strings, import table) and review sandbox summaries  
- Extract IOCs and map behaviors to MITRE ATT&CK  
- Propose containment, remediation, and detection rules (YARA/Sigma)  
- Reflect on lessons learned and professional development  

---

###  Methodology  
Each step is documented with reasoning and actions taken:

1. **Initial Enrichment**: Queried VirusTotal using SHA256 hash  
2. **Malware Category**: Classified as Trojan/Stealer based on AV labels and behavior  
3. **Filename Discovery**: Extracted from metadata and sandbox reports  
4. **First-Seen Timestamp**: `2023-10-06 04:41:50 UTC`  
5. **MITRE Mapping**: T1005 (Data from Local System), T1071.001 (Web Protocols)  
6. **DNS Resolution**: Sample resolved `facebook.com`  
7. **C2 Details**: IP `77.91.124.55`, Port `1971`, Bot ID `frant`  
8. **YARA Rule**: `detect_Redline_Stealer` by Varp0s  
9. **Alias Correlation**: RedLine = RecordStealer (via Malpedia)  
10. **Privilege Escalation**: Use of `ADVAPI32.dll` for token manipulation  

---

###  Results / Outcomes  
| Key Finding | Details |
|-------------|---------|
| Malware Type | Trojan / Info-Stealer (RedLine / RecordStealer) |
| SHA256 | `248FCC901AFF4E4B4C48C91E4D78A939BF681C9A1BC24ADDC3551B32768F907B` |
| Filenames | `Wextract.EXE`, `malicious.exe`, `red.exe` |
| First Seen | `2023-10-06 04:41:50 UTC` |
| C2 IP/Port | `77.91.124.55:1971` |
| Bot ID | `frant` |
| Targeted Browser | Comodo IceDragon |
| Privilege API | `ADVAPI32.dll` (AdjustTokenPrivileges, OpenProcessToken) |
| YARA Rule | `detect_Redline_Stealer` by Varp0s |
| DNS Behavior | Resolved `facebook.com` during execution |

---

### Screenshots  
- **Figure 1**: VirusTotal overview
- <img width="646" height="380" alt="image" src="https://github.com/user-attachments/assets/e7db48a1-8ad9-4152-92e7-1386e34c0e67" />
- **Figure 2**: VirusTotal first-seen timestamp
- <img width="940" height="288" alt="image" src="https://github.com/user-attachments/assets/9c4d7476-b752-4278-af6b-9b8b46f969cc" />
- **Figure 3**: MalwareBazaar YARA rule and alias mapping
- <img width="723" height="404" alt="image" src="https://github.com/user-attachments/assets/658aba5f-5b74-43f0-8269-6a1b1b42680a" />
 

---

###  Reflection  
As a cybersecurity student, this lab helped me bridge theory with practice. I gained hands-on experience in threat intelligence workflows, malware triage, and IOC extraction using VirusTotal and MalwareBazaar. Mapping behaviors to MITRE ATT&CK techniques—like T1005 and T1071.001—reinforced my understanding of attacker tactics. Identifying privilege escalation through ADVAPI32.dll deepened my technical insight.

This project strengthened my SOC skills in triage, IOC production, and incident response handoff. I’m now more confident presenting technical evidence and collaborating across teams. If I were to repeat the task, I’d expand into memory forensics, automate threat intel lookups via APIs, script IOC exports, and improve timestamp and chain-of-custody documentation for formal IR workflows.
