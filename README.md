# SplunkQueries

This is a collection of Splunk queries I've made over time that can ben useful for anyone. As time goes on I'll continue to add to this.

Attached to this repo are:
 - modifications to the input files for Windows endpoints. Modifications include whitelisting of preferred Event IDs to forward, trimming off useless data on logs, and splitting 4688 events from the rest of my indexes. 
 - The logging levels of your Windows domain
 - Syslog-ng configuration for anything using syslog and not a universal forwarder

### Windows local account logon
```
index=wineventlog sourcetype="WinEventLog" EventCode=4624 Logon_Type!=3
| fields _time Account_Name Account_Domain ComputerName Logon_Type src_ip Process_Name Workstation_Name
| eval LocalDomain=mvindex(Account_Domain,1)
| eval LocalUser=mvindex(Account_Name,1)
| where LocalDomain == Workstation_Name
| eval Logon_Type=case(Logon_Type="2","Interactive Logon",Logon_Type="4","Scheduled Task",Logon_Type="5","Service Startup",Logon_Type="7","Unlocked Station",Logon_Type="8","NetworkCleartext",Logon_Type="9","RunAs",Logon_Type="10","RemoteInteractive (RDP)")
| table _time LocalUser LocalDomain ComputerName Logon_Type src_ip Process_Name
```
<br />

### Carbon Black bypass  
```
sourcetype=wineventlog source="WinEventLog:Application" SourceName=CbDefense Message=*Bypass*
| eval Messages = case(LIKE(Message, "%ExitBypass%"), "now Protecting",
                       LIKE(Message, "%EnterBypass%"), "no longer protecting")
| table ComputerName SourceName Messages
```
<br />

### Palo Alto GlobalProtect Private IP address
```
index=palo_alto user=* sourcetype=pan:globalprotect (stage=connected OR stage=logout)
| fields user stage private_ip machine_name
| stats latest by user
```
<br />

### Palo Alto GlobalProtect Pre-Logon IP address
```
index=palo_alto user=pre-logon sourcetype=pan:globalprotect (stage=host-info OR stage=logout)
| fields user private_ip machine_name stage
| eval ConnectionStatus=case(stage="host-info","Connected",stage="logout","No Longer Connected")
| stats latest by machine_name
```
<br />

### AD user account creation|deletion|enabled|disabled
```
EventCode=4720 OR EventCode=4722 OR EventCode=4725 OR EventCode=4726 sourcetype=WinEventLog source=WinEventLog:Security
| fields host Subject_Security_ID Target_Account_Domain New_Account_Domain Target_Account_Name SAM_Account_Name name _time
| eval target=coalesce(Target_Account_Name,SAM_Account_Name)
| eval domain=coalesce(Target_Account_Domain,New_Account_Domain)
| fields host Subject_Security_ID domain target name _time
```
<br />

### AD user added to Domain Admin group
```
index=wineventlog sourcetype=WinEventLog source=WinEventLog:Security (EventCode=4728 OR EventCode=4729) (Group_Name="ServiceAccount" OR Group_Name="Domain Admins")
| table host Subject_Security_ID Group_Name Member_Security_ID name _time
```
<br />

### Admin sign-in to Okta Portal
```
index=okta displayMessage="User accessing Okta admin app" sourcetype="OktaIM2:log"
| table src_user body dvc outcome.result request.ipChain{}.geographicalContext.state request.ipChain{}.geographicalContext.country
| rename request.ipChain{}.geographicalContext.state AS State, request.ipChain{}.geographicalContext.country AS Country
```
<br />

### Sign-in to Okta from outside US
```
index=okta sourcetype="OktaIM2:log" "client.geographicalContext.country"!="United States"
| table client.geographicalContext.country src_ip src_user body dvc outcome.result _time
| rename client.geographicalContext.country AS Src_Country, outcome.result AS Outcome
```
