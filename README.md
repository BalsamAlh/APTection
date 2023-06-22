# APTection
APTection is a system that detects Advanced Persistent Threats (APTs) in their early stages. Takes advantage of MITRE ATT&CK, Use logs as a reliable source to spot APT activities. Analyze Windows Event Logs through sigma rules and event conditions. From this analysis, the system will produce a matching ID between the techniques discovered in the log file and those from the database. Attribution will then pinpoint to APT groups most likely responsible for attacking the organization, displayed in an easy-to-understand dashboard. 

----------------
open source tool that is available to you without any restrictions, 
a threat hunting tool with high accuracy that can detect 
APTs in network environments, and a very useful tool for 
teams conducting forensic investigations, incidents
response, and threat hunting. It can help you discover any 
suspicious activity you are unaware of before it develops 
into a significant incident. And display the result in an easyto-understand dashboard.
--------
Authers:
Balsam Alharthi https://www.linkedin.com/in/balsam-alharthi
Bushra Alghamdi
Malak Masad
Joud Hawari
# Features of the tool:
At log analysis, we leverage two powerful tools to aid us in 
building our tool: Apt Hunter [8] and Threat Hound [11]. 
Both support Windows Event Logs exported as EVTX. 
making them the ideal choice for us. Apt Hunter provides 
more than 60 use cases, dive into security and terminal 
services logs, and conveniently outputs the results in an 
Excel sheet, each log type has its own worksheet. Threat 
Hound is capable of dynamically adding new Sigma rules 
for detection purposes, due to its specialized Python 
backend for both Sigma rules and EVTX parsing/matching. 
This allows us to add our own custom Sigma rules. We 
created more than 1,500 custom detection rules for SIGMA 
which can be found on our GitHub page, correlate it with 
APTection. At APTection, we process Windows Event Logs 
to detect events with potential APT activity. We use the 
industry standard Indicator of Attack methodology and 
analyze log types such as Security, System, PowerShell, 
Powershell_Operational, ScheduledTask, WinRM, 
TerminalServices and Windows Defender. Our system 
generates a Report.xlsx detailing any events discovered 
from the logs as well as a TimeSketch.csv file that can be 
uploaded to Timesketch for more in-depth timeline analysis. 
This allows us to provide greater insight into potential 
attacks on your systems.

-----------------
Features of the tool
More than 50 detection rules included
You can easily add any detection rule
The result display in easy to understand dashboard
Next stage of the attack


# Installiton

# How to Use APTection
# Demo
https://github.com/BalsamAlh/APTection/assets/121826710/3ea3d276-4e91-47e1-a26f-3eb1e39ff684
# The result will be available in two sheets :
