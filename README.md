# ITECH1502 - Cybersecurity Portfolio Final Project  
**Student:** Bernie Ybanez  
**Student ID:** 30405887  
**Project Title:** Investigating Red Stealer — Threat Intelligence & Malware Analysis (SOC Lab)  

---

##  Summary
In this lab, I investigated a suspicious executable as part of a SOC-style threat-intel lab, starting from its SHA256 (`248FCC901AF…68F907B`) and enriching the sample with vendor metadata, sandbox summaries, and network artefacts from tools like **VirusTotal** and **MalwareBazaar**.  

By combining static and dynamic analysis, I extracted actionable Indicators of Compromise (IOCs), identified malware family aliases, and mapped observed behaviours to **MITRE ATT&CK** techniques.  

The sample was classified as a **Trojan / Information Stealer** linked to the **RedLine / RecordStealer** family and was observed under several filenames, including `Wextract.EXE`, `malicious.exe`, and `red.exe`.  

Key findings include:
- **First-seen timestamp:** 2023-10-06 04:41:50 UTC  
- **C2 endpoint:** 77.91.124.55:1971  
- **MITRE Technique:** T1005 – Data from Local System  
- **Privilege manipulation APIs:** ADVAPI32.dll imports (e.g., `AdjustTokenPrivileges`, `OpenProcessToken`)  

The final deliverable includes:
- IOC Table  
- MITRE ATT&CK Mapping  
- Example YARA and Sigma Rules  
- Containment and Remediation Recommendations  

This project reinforced **NIST CSF** functions — *Identify, Detect, Respond* — and strengthened my ability to produce operational intelligence for SOC and IR teams.

---

##  Introduction
**Portfolio Link:** `30405887/cyber-portfolio-Bernie-Ybanez-30405887`  
**Hands-on Platform:** [CyberDefenders – Red Stealer Lab](https://cyberdefenders.org/blueteam-ctf-challenges/red-stealer/)  

**Why Selected:**  
This lab simulates a real-world SOC threat intelligence workflow analysing a suspicious binary/hash, extracting IOCs, identifying C2 infrastructure, and producing operational guidance for Incident Response. It directly complements learning outcomes in incident response, threat intelligence, and digital forensics.

---

##  Problem / Challenge
A suspicious executable was discovered on an endpoint and suspected to be part of a **C2-enabled information-stealer campaign**.  

As a Threat Intelligence Analyst within the SOC, my tasks were to:
- Analyse the file hash and classify the malware  
- Identify malware family and IOCs  
- Determine C2 endpoints and communication behaviour  
- Map behaviours to MITRE ATT&CK techniques  
- Produce actionable intelligence for SOC and IR teams  

---

##  Project Goals / Objectives
- Use VirusTotal and MalwareBazaar to classify the sample and gather metadata  
- Perform safe static analysis (hashing, strings, import table) and review sandbox summaries  
- Extract IOCs and map behaviours to MITRE ATT&CK  
- Propose containment, remediation, and detection rules (YARA/Sigma)  
- Reflect on lessons learned and professional development  

---

## ⚙️ Methodology  

### Step 1 – Input & Initial Enrichment  
Queried **VirusTotal** using the SHA-256 hash to obtain vendor detection labels, metadata, and sandbox behaviour summaries.  

### Step 2 – Determine Malware Category  
Reviewed AV vendor tags such as *Trojan*, *RedLine*, and *Stealer*. Sandbox confirmed data collection and C2 communication.  

### Step 3 – Identify Filenames  
Extracted from VirusTotal metadata: `Wextract.EXE`, `malicious.exe`, `red.exe`.  

### Step 4 – Establish First Submission Timestamp  
First uploaded: **2023-10-06 04:41:50 UTC**  

### Step 5 – Map Behaviour to MITRE ATT&CK  
Behaviours observed:
- File and registry access  
- Browser data scraping  
- Credential harvesting  
- Local file collection  

Mapped to:
- **T1005** – Data from Local System  
- **T1071.001** – Web Protocols  

### Step 6 – Identify Domain Name Resolution  
Detected DNS queries to `facebook.com` — likely used to mimic legitimate traffic.  

### Step 7 – Extract C2 IP and Port  
Decoded C2 endpoint: **77.91.124.55:1971** with **bot ID "frant"**.  

### Step 8 – Locate YARA Rule and Author  
Found rule: `detect_Redline_Stealer` by **Varp0s** in MalwareBazaar.  

### Step 9 – Correlate Aliases via Malpedia  
Confirmed **RecordStealer** as alias for **RedLine Stealer**.  

### Step 10 – Determine Imported DLLs and Privilege Escalation APIs  
Detected `ADVAPI32.dll` functions:
- `AdjustTokenPrivileges`  
- `OpenProcessToken`  
- `LookupPrivilegeValueA`  

Indicates potential privilege escalation attempts.  

---

## 📊 Results / Outcomes  

| **Key Finding** | **Details** |
|------------------|-------------|
| **Malware Type** | Trojan / Info-Stealer (RedLine / RecordStealer) |
| **SHA256** | 248FCC901AFF4E4B4C48C91E4D78A939BF681C9A1BC24ADDC3551B32768F907B |
| **Filenames** | Wextract.EXE, malicious.exe, red.exe |
| **First Seen** | 2023-10-06 04:41:50 UTC |
| **C2 IP/Port** | 77.91.124.55:1971 |
| **Bot ID** | frant |
| **Targeted Browser** | Comodo IceDragon |
| **Privilege API** | ADVAPI32.dll (AdjustTokenPrivileges, OpenProcessToken) |
| **YARA Rule** | detect_Redline_Stealer by Varp0s |
| **DNS Behaviour** | Resolved facebook.com during execution |

---

## 🧠 Screenshots
<img width="940" height="553" alt="image" src="https://github.com/user-attachments/assets/134a629c-e9ea-4ffe-b36b-af4ceab20426" />
<img width="940" height="359" alt="image" src="https://github.com/user-attachments/assets/5f532e3d-5f9c-4386-927a-06c3cc21d5bc" />
<img width="940" height="288" alt="image" src="https://github.com/user-attachments/assets/8c0b33f2-f01c-4744-bb1a-1dd18bb2e0d3" />
<img width="940" height="811" alt="image" src="https://github.com/user-attachments/assets/c42abb62-33f0-43ec-ab29-fe06fab8ed07" />
<img width="940" height="607" alt="image" src="https://github.com/user-attachments/assets/ba40e835-ebbb-4231-9488-fac673f4764e" />
<img width="940" height="493" alt="image" src="https://github.com/user-attachments/assets/c65411a9-02f4-4967-a5db-0df0585b41a5" />
<img width="940" height="533" alt="image" src="https://github.com/user-attachments/assets/a6d98a62-6eb3-4158-a8e4-3b9601cb9b24" />
<img width="940" height="525" alt="image" src="https://github.com/user-attachments/assets/b0a31157-e242-4636-b3aa-108d946ffb4b" />
<img width="940" height="649" alt="image" src="https://github.com/user-attachments/assets/2b771c25-2b64-4dea-886d-fe2f24742612" />
<img width="816" height="403" alt="image" src="https://github.com/user-attachments/assets/ca7bf032-f6d5-49e6-b12f-5332f0f61529" />
<img width="763" height="1041" alt="image" src="https://github.com/user-attachments/assets/06fbbca7-12df-46c2-bb96-b34601789e8f" />














![VirusTotal Detection](images/virustotal-detection.png)
![First Submission](images/first-seen.png)
![Malpedia Alias](images/malpedia-alias.png)
