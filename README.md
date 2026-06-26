# APT28-Blue-delta-emulation

# APT28 overview 

## 1. Group Identity & Attribution

| Category | Description |
|----------|-------------|
| **APT28** |  is a Russian state-sponsored cyber espionage group associated with military intelligence operations. |
| **Aliases** | IRON TWILIGHT, SNAKEMACKEREL, Swallowtail, Group 74, Sednit, Sofacy, Pawn Storm, Fancy Bear, STRONTIUM, Tsar Team, Threat Group-4127, TG-4127, Forest Blizzard, FROZENLAKE, ruesomeLarch |
| **Military Unit** | APT28 is associated with GRU unit 26165 |
| **Chain of Command** | The full chain of command is not fully disclosed. However, several sanctioned/indicted individuals are known: |
|  | **Commanding Officer:** Viktor Borisovich Netyksho |
|  | **Senior Leadership:** Boris Antonov (Head of Operations), Sergey Morgachev (Deputy Head of Directorate) |
|  | **Operations Team:** Ivan Sergeyevich Yermakov, Andrey Eduardovich Baranov |
|  | **Infrastructure Team:** Artem Malyshev, Nikolai Yuryevich Kozachek, Pavel Yershov, Sergey Vasyuk |
|  | **Close-Access Operations:** Aleksei Morenets |
|  | **Other Officers:** Dmitry Badin, Georgy Roshka, Aleksey Potemkin |
| **Motivation** | Political and military espionage, election interference, and influence operations aligned with Russian state policy |
| **Strategic Objectives** | Intelligence gathering on geopolitical strategies, influencing political processes, undermining adversarial alliances, and exfiltrating sensitive government/military data |
| **Relationship with Sandworm Team** | :contentReference[oaicite:2]{index=2} and APT28 are separate GRU units. APT28 focuses on espionage while Sandworm focuses on destructive cyber operations. They may operate in complementary or coordinated campaigns. |
| **GRU Units Overview** | Unit 26165 (APT28), Unit 29155 (covert operations), Unit 35555 (psychological research), Unit 54777 (72nd Special Service Center), Unit 74455 (Sandworm Team) |

## 2.Historical Operations

| Operation | Year | Target | Techniques Used |
|----------|------|--------|-----------------|
| U.S. Presidential Election Interference | 2016 | DNC, Hillary Clinton campaign | T1566.001 – Spearphishing attachment<br>T1204.002 – Malicious file execution<br>T1003.001 – LSASS memory dumping<br>T1041 – Exfiltration over C2 |
| WADA / USADA Operations | 2014–2018 | Anti-doping agencies | T1566.001 / T1566.002 – Spearphishing attachment/link<br>TA0006 – Credential access via phishing<br>T1567 – Exfiltration over web services |
| OPCW / Spiez Laboratory Attacks | 2018 | Chemical weapons investigators | T1595 – Active scanning<br>T1046 – Network service discovery |
| BlueDelta Credential Harvesting | 2025 | Turkish energy sector, European think tanks | T1566.002 – Spearphishing link<br>T1608.005 – Stage capabilities (link target)<br>T1557 – Adversary-in-the-middle<br>T1555.003 – Credentials from web browsers |
| RoundPress Cyberespionage Campaign | 2023 | Government, military units, defense firms | T1566.001 – Spearphishing attachment<br>T1190 – Exploit public-facing application<br>T1555.003 – Credentials from browser<br>T1114 – Email collection<br>T1041 – Exfiltration over C2 |

 ## 3. Technical  TTP analysis 

| MITRE Techniques ID | Technique Name | APT28 Specific Implementation |
|--------------------|----------------|-------------------------------|
| T1566.001 | Spearphishing Attachment | Phishing emails were sent with subject "Upcoming Defense events February 2018". The sender address was spoofed to resemble events@ihsmarkit.com, and the email contained a malicious Excel XLS attachment named "Upcoming Events February 2018.xls". |
| T1204.001 | Malicious Link | A spearphishing campaign targeted personal email accounts of individuals associated with the Hillary Clinton presidential campaign, including the campaign chairman, using shortened links redirecting to spoofed Google login pages. |
| T1003.001 | LSASS Memory Dumping | The `rundll32.exe` utility was used to execute the MiniDump function exported by `comsvcs.dll` to dump the memory of the LSASS process. |
| T1134 | Token Manipulation | APT28 exploited a Windows kernel vulnerability (CVE-2015-1701) after initial compromise via spearphishing documents. The exploit allowed attackers to obtain the SYSTEM access token and assign it to a malicious process, elevating privileges to NT AUTHORITY\SYSTEM. |
| T1041 | Exfiltration over C2 | Collected system information, screenshots, email bodies, contacts, and credentials were transmitted to C2 servers via HTTPS channels or HTTP POST requests. |
| T1070.004 | Indicator Removal on Host / Redirect to Legitimate Site | A spearphishing campaign used shortened URLs targeting energy, government, and policy organizations in 2025. After clicking, users were briefly redirected to legitimate PDF documents before being redirected to spoofed login pages impersonating Microsoft OWA or Google. |

# Executive summury 

On 22-06-2026 at approximately 06:12:15 AM, a malicious file delivered via phishing email executed on the DESKTOP-HDS5IEK workstation with TESTLAB.LOCAL domain. The attack silently performed a discovery activities targeting users, network and security control products. Next, it escalated privileges and successfully dumped credentials from memory. Then, the stolen data was exfiltrated through C2 Gmail channel. 

Severity assessment:critical

Affected assets:
- Hostname: DESKTOP-HDS5IEK
- Domain: TESTLAB.LOCAL
- Operating system: Windows 10
- Asset type:Workstation
- Compromised accounts: Omrim 

Business Impact:
- Omrim account credentials are stolen
- The attacker has full visibility of the network and security controls 
- Exfiltration of stolen data through C2 Gmail channel

### Tools used 

| Tools | Description |
|------|-------------|
| Wireshark | Used to capture network traffic during the APT28 simulation |
| Sysmon | Used for endpoint monitoring |
| DumpIt | Used to capture the volatile memory |
| Volatility 3 | Used to extract artifacts from memory image |
| Mimikatz | Used by NulltackKatz.py to dump credentials from lsass memory |
| NulltackKatz.py | Used to emulate APT28 attack |

### Learning Objectives

- Detect spearphishing indicators in email headers and attachments  
- Identify LSASS credential dumping via Sysmon Event ID 10  
- Analyze memory dumps using Volatility 3 for Mimikatz and nulltackKatz artifacts  
- Trace exfiltration patterns in network traffic  
- Map attack actions to the MITRE ATT&CK framework  
- Write detection rules for APT28 TTPs

## Tasks
### 1.Lab Setup

A Lab environment was prepared to support the simulation and analysis of APT28 simulation scenario.  
A structured directory was created to organize investigation artifacts, including:  
- Logs directory: used to store logs generated during the APT28 emulation  
- Evidence directory: used to store collected evidence like memory acquisition and network traffic capture  

For data exfiltration, a Gmail account was configured with 2 factor authentication enabled and application password generated to support automated authentication. Security monitoring tools (Wireshark, Sysmon) were enabled to ensure the visibility of the system and the network during the scenario.  

### 2.Attack execution

The attack successfully executed by running python NultackKatz.py command:
<br><img width="900" height="392" alt="image" src="https://github.com/user-attachments/assets/123760d7-663e-4a88-b8ec-143ad12a07ca" /><br>

<br><img width="898" height="485" alt="image" src="https://github.com/user-attachments/assets/d4b8768b-4859-4360-a90e-7c58f9060702" /><br>

<br><img width="914" height="783" alt="image" src="https://github.com/user-attachments/assets/c1da8375-2c6e-4deb-a640-958b8645c28e" /><br>

<br><img width="914" height="311" alt="image" src="https://github.com/user-attachments/assets/28e6266e-09a9-4208-ac85-6f6d1b5504d2" /><br>

### 3.Investigation
#### 3.1.Phase1: Spearphishing email T1566.001

The analysis of the phishing email generated in logs directory indicated that the email:
-	was sent from IT security associated to security@payroll-update.com email address
-	reply-to another email address it-security@noreply.com which different from FROM address
-	contained an attachment named NulltackKatz.py
-	claimed that an urgent update for the Payroll System Security is required. 
-	Mapped to MITRE ATT&CK technique T1566.001: spearphishing attachment<br>

The reply-to address is used to receive responses from users who want to respond to received email. It contains 2 parts:
-	Name: it-security – usually attackers use trusted name to appear legitimate 
-	Domain :noreply.com – legitimate companies use domains like campagny-name.com<br>

APT28 abuse legitimate and trusted email addresses in FROM while they hide the suspicious email address from which they will receive responses from users in the reply-to.

<br><img width="953" height="588" alt="image" src="https://github.com/user-attachments/assets/40e5bb0c-454c-4fe3-86bb-3b8241221359" /><br>

#### 3.2.Phase2: Malicious File execution

The analysis of process creation events Event ID1 confirmed: 
1.	The execution of NulltackKatz.py by python.exe under the DESKTOP-HDS5IEK\omrim user context:
-	ParentIamge : C:\Users\omrim\AppData\Local\Programs\Python\Python313\python.exe
-	CommandLine :C:\Users\omrim\AppData\Local\Programs\Python\Python313\python.exe" .\NulltackKatz_v1.3_special_Ver_3.py

<br><img width="945" height="497" alt="image" src="https://github.com/user-attachments/assets/fcfa73ed-587a-4217-9e5b-1001d7f8b984" /><br>

2.	The execution of malicious mimikatz.exe process by python.exe under the DESKTOP-HDS5IEK\omrim user context:
-	Image: C:\Tools\mimikatz\x64\mimikatz.exe
-	ParentImage: C:\Users\omrim\AppData\Local\Programs\Python\Python313\python.exe
-	Command Line: C:\Tools\mimikatz\x64\mimikatz.exe privilege::debug sekurlsa::logonpasswords exit

<br><img width="945" height="480" alt="image" src="https://github.com/user-attachments/assets/b42d01e6-cd6f-491a-8b30-c0207f752994" /><br>

#### 3.3.Phase3:Discovery

The analysis of created processes EventID1 confirmed the discovery phase performed by cmd.exe, child process of  python.exe where multiple command lines were passed:
-	Image: C:\Windows\System32\cmd.exe
-	ParentImage: C:\Users\omrim\AppData\Local\Programs\Python\Python313\python.exe
-	CommandLine: 
o	C:\Windows\system32\cmd.exe /c "net user" : to display information about user accounts
o	C:\Windows\system32\cmd.exe /c "ipconfig /all": to display network configuration
o	C:\Windows\system32\cmd.exe /c "tasklist": to display running processes 
o	C:\Windows\system32\cmd.exe /c "net session": to display information about sessions 
-	ParentCommandLine: C:\Users\omrim\AppData\Local\Programs\Python\Python313\python.exe   .\NulltackKatz_v1.3_special_Ver_3.py

<br><img width="945" height="463" alt="image" src="https://github.com/user-attachments/assets/e60a7bff-c2c9-4ce6-a580-1304f5a9618c" /><br>

#### 3.4.Phase4:Lsass memory analysis credentials dump

The analysis of process access events confirmed the access of lsass.exe process through mimikatz.exe process: 
-	SourceImage: : C:\Tools\mimikatz\x64\mimikatz.exe
-	TargetImage: C:\Windows\system32\lsass.exe
-	GrantedAccess: 0x1010
-	SourceUser: DESKTOP-HDS5IEK\omrim<br>

The granted access  0x1010 involves two access rights, including: 
-	PROCESS_VM_READ (0x0010):  read lsass.exe process memory 
-	PROCESS_QUERY_LIMITED_INFORMATION (0x1000): retrieve basic information about lsass.exe process<br>

This event is primary IOC of credential dump because the suspicious process mimikatz reads and retrieves informations from lsass memory.

<br><img width="983" height="513" alt="image" src="https://github.com/user-attachments/assets/2cafaaa1-b70b-411c-b051-69f1cde08eb9" /><br>

The analysis of memory image revealed:
-	Neither mimikataz.exe nor NulltackKataz.exe processes were observed in windows.psscan output.
-	No mimikatz handle opened  lsass was observed 
-	No evidence of an open handle from mimikatz.exe to lsass.exe was identified in the memory
-	No mimikatz commands were observed in the windows.cmdline output

##### Findings:

-	Event ID1 confirmed execution of NulltackKatz.py by python.exe(PID 11728), the creation of mimikatz.exe process( PID 12086) and execution of mimikatz command “privilege::debug sekurlsa::logonpasswords” 
-	Event ID10 confirmed that mimikatz.exe accessed lsass.exe access to lsass.exe 
-	Sysmon logs provide clear evidence that the mimikatz was executed and successfully accessed lsass.exe. The absence of mimikatz process, handle and cmdline suggests that mimikatz executed and exited quickly before memory acquisition or the memory address was reallocated by the OS.

<br><img width="945" height="70" alt="image" src="https://github.com/user-attachments/assets/82775eb7-59c1-4954-8084-b375c8528e61" /><br>

<br><img width="945" height="382" alt="image" src="https://github.com/user-attachments/assets/521b9a22-e95e-4fe3-9ed3-cd3f6329a1cb" /><br>

<br><img width="945" height="397" alt="image" src="https://github.com/user-attachments/assets/36eda7a9-3ce0-4356-af76-f0fdafd80dd2" /><br>

<br><img width="945" height="305" alt="image" src="https://github.com/user-attachments/assets/d557c715-ab1d-4524-b165-60aeeb882ee8" /><br>

#### 3.5.Phase5:Exfiltration:Network Traffic analysis

# C2 Communication Flow Analysis

| Sequence | Explanation |
|----------|-------------|
| DNS resolution | - The attacker 192.168.217.165 queried A record of smtp.gmail.com domain |
| TLS Handshake | - The attacker initiated TLS handshake with C2 mail server 142.251.127.109<br>- TLS handshake successfully completed |
| SMTP communication | - The attacker initiated SMTP communication by sending EHLO DESKTOP-HDS5IEK.localdomain message to the C2 mail server to identify itself<br>- The attacker sent STARTTLS command to establish secure communication<br>- The attacker sent Auth command to authenticate to the C2 mail server<br>- The attacker identified the sender and recipient mail (mail from, rcpt to)<br>- The attacker sent data message to start sending data to the C2 mail server<br>- The stolen credentials were then exfiltrated from 192.168.217.165 via email address omrimaha489@gmail.com to C2 server 142.251.127.109 over SMTP port 587, with the subject: [APT28-BLUEDELTA-BLUEDELTA_20260621_231156] Compromised: DESKTOP-HDS5IEK - REAL Credentials Exfiltrated |

<br><img width="983" height="527" alt="image" src="https://github.com/user-attachments/assets/8c65dc2d-6848-43fd-8b27-ca297faba516" /><br>

### 4.MITRE ATT&CK mapping, attack timeline and supporting evidence


| Timestamps | Technique ID, Name | Detection Method | Evidence |
|------------|--------------------|------------------|----------|
| - | T1566.001 - Spearphishing attachment | Monitor `.py` file extension through security email gateway<br>Inspect FROM and reply-to email header | Malicious file received by email, successfully downloaded and executed leading to memory credential dump and exfiltration |
| 06:12:15.735 UTC | T1204.002 - Malicious File Execution | Monitor Sysmon Event ID process creation (mimikatz.exe and NulltackKatz.py) | Execution of NulltacKatz.py process by python.exe process confirmed by Sysmon |
| 06:12:16.095 UTC | T1087.001 - Local account discovery | Monitor Sysmon Event ID 1 cmd.exe process creation with commandLine `net user`, `net session` | Information about user accounts was exfiltrated: omrim and Administrator |
| 06:12:16.133 UTC | T1016 - Network configuration discovery | Monitor Sysmon Event ID 1 cmd.exe process creation with commandLine `ipconfig` | Information about network configuration was exfiltrated: IP configuration and Ethernet |
| 06:12:16.162 UTC | T1057 - Process discovery | Monitor Sysmon Event ID 1 cmd.exe process creation with commandLine `tasklist` | No AV/EDR detected in exfiltration report |
| 06:12:16.276 UTC | T1134 - Access token manipulation (SeDebugPrivilege) | Monitor Sysmon Event ID 1 mimikatz.exe process creation with commandLine `debug::privilege` | Mimikatz executed confirming privilege escalation requiring administrator privileges |
| 06:12:16.474 UTC | T1003.001 - OS credential dumping (LSASS memory) | Monitor Sysmon Event ID 10 (lsass.exe access) | NTLM hash exfiltrated: NTLM:048df091f487292d9a73f232fcf99bac |
| 06:12:18.058 UTC | T1041 - Exfiltration over C2 channel (Gmail) | Monitor Event ID 3 (outbound SMTP traffic over TLS port 587) | Exfiltration received through email and confirmed through network analysis (PCAP) |

### 5. IOC

| Category | Details |
|----------|--------|
| IPs | 192.168.217.165 : attacker’s IP<br>142.251.127.109 : C2 channel used for exfiltration (outgoing Gmail server) |
| URLs | https://drive.google.com/file/d/1tpFjOmPWBGw21YLneFRgqN6st8IehZd5/view?usp=drive_link : link hosting malicious server |
| Domains | security@payroll-update.com : suspicious email address used to send malicious file<br>it-security@noreply.com : suspicious email address used to receive responses from the victim<br>omrimaha489@gmail.com : C2 channel used to receive exfiltration<br>smtp.gmail.com : requested C2 mail server |
| Ports | 587 : secure SMTP port used by C2 for exfiltration |
| Files | Name: NulltackKatz.py<br>Size: 27 KB<br>SHA256: 56F5D26114FD75B45385476D308DD4273732C45D8BC54516E981BB7FB8985BDA<br><br>Name: mimikatz.exe<br>SHA256: 92804FAAAB2175DC501D73E814663058C78C0A042675A8937266357BCFB96C50 |
| Affected Systems | Hostname: DESKTOP-HDS5IEK<br>OS: Windows<br>OS Version: 10.0.19045 |

### 6.Defensive recommendations
#### 6.1. Rule tuning 

<br><img width="983" height="1012" alt="image" src="https://github.com/user-attachments/assets/3f9585b1-fb84-42ce-a1d4-192ffc216fc9" /><br>

<br><img width="945" height="292" alt="image" src="https://github.com/user-attachments/assets/2fd8f306-4691-4b5b-ae92-870c156dec14" /><br>

#### 6.2.Recommendations 

Containment 
-	Isolate the DESKTOP-HDS5IEK from the network to prevent further spread across the network
-	Disable Omrim compromised account and reset credentials 
-	Block outbound connection to SMTP Gmail<br>
  
Eradication:
-	Remove the malicious file NulltackKatz_v1.3_special_Ver_3.py from the system 
-	Block all incoming and outgoing traffic from and to  attacker’s IP 192.168.217.165  at firewall
-	Block omrimaha489@gmail.com and it-security@noreply.com email address through email security gateway 
-	Implement SPF, DKIM and DMARC authentication protocols to prevent spoofing.
-	Improve 2FA by implementing passkeys not only SMS . Passkeys help prevent remote phishing by replacing phishable methods like passwords, SMS, and email codes
-	For privileged accounts, disable legacy authentication protocols ( older protocols that do not support security features) such as NTLM and basic authentication .

### 7.Lessons learned

-	Regular user awareness training should be performed to educate people identifying and recognizing phishing emails, as phishing was identifying  the initial attack vector in this incident.
-	Network traffic should be properly monitored and controlled, uncontrolled traffic could be exploited by attackers for malicious activities such as C2 communication and filtering
-	Security email controls such as filtering and attachments scans should be strengthened to reduce phishing incidents

### 8.Knowledge Graph 

<br><img width="983" height="706" alt="image" src="https://github.com/user-attachments/assets/e4b6d84a-b5b0-48e4-bba3-7fc7bb511c51" /><br>

# Conclusion:
All tasks were successfully performed and completed during lab exercise. <br>

-	APT28 emulation was successfully executed, demonstrating the full attack chain from initial access through phishing email to data exfiltration. 
-	Sysmon endpoint monitoring was properly configured, enabling the detection and analysis of NulltackKatz.py and mimikatz activity.
-	Network traffic monitoring controls were absent, allowing the exfiltration of stolen data through C2 Gmail account.
-	Memory forensic was performed, without mimikatz artifacts recovered.
-	Defensive detection rules were developed to enhance the system visibility and improve monitoring capabilities .
-	Recommendations were provided to contain the same incident and reduce the likelihood of future compromises .<br>
  
The scenario provided a valuable insight into APT28 TTP tactics, techniques and tactics, while strengthened my skills in threat detection, incident response and memory forensic image and analysis.





