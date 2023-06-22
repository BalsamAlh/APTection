![APTecti n](https://github.com/BalsamAlh/APTection/assets/121826710/242fe7cb-99a1-43dd-afd9-83959fc96e29)
# APTection
APTection is a threat hunting tool with high accuracy that detects Advanced Persistent Threats (APTs) in their early stages. Takes advantage of MITRE ATT&CK, Use logs as a reliable source to spot APT activities. Analyze Windows Event Logs through sigma rules and Use cases. From this analysis, the system will produce a matching ID between the techniques discovered in the log file and those from MITRE ATT&CK database. Attribution will then pinpoint to APT groups most likely responsible for attacking the organization, displayed in an easy-to-understand dashboard.

---------------------
Authers:
[Balsam Alharthi](https://www.linkedin.com/in/balsam-alharthi),
Bushra Alghamdi,
Malak Masad,
Joud Hawari.
# APTection Features
- Useful tool for teams conducting forensic investigations, incidents response, and threat hunting. It can help you discover any suspicious activity you are unaware of before it develops into a significant incident.
-	Support windows event logs exported as EVTX and CSV.
-	Collect and analyze (Sysmon, Security, System, Sigma Rules, Powershell, Powershell Operational, ScheduledTask, WinRM, TerminalServices, Windows_Defender).
-	Over 80 use cases are included.
-	Dynamically adding Sigma rules to detection rule sets.
-	created more than 1,500 custom Sigma rules  for detection.
-	The current and next stages in the APT lifecycle (cyber kill chain) are displayed.
-	The result display in easy to understand dashboard, It showcases the top three APT groups that have been detected within your system. 



# Results:
 
1. **Excel sheet** detailing any events discovered from the logs, each log type has its own worksheet.
2. **TimeSketch.csv** file that can be uploaded to Timesketch for more in-depth timeline analysis. This allows us to provide greater insight into potential attacks on your systems.
3. **Dashboard** to show a comprehensive overview of data. This includes the top three APT groups identified with corresponding accuracy percentages, in addition to the current stage and expected next stage.

# Installiton
```
 $ git clone
 $ cd APTection
 $ pip install -r requirements.txt
 $ python3 APTection.py
```
To see the result on dashboard use this command
```
$ shiny run --reload dashboard.py
```
# Demo
https://github.com/BalsamAlh/APTection/assets/121826710/3ea3d276-4e91-47e1-a26f-3eb1e39ff684

