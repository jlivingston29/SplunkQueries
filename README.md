# SplunkQueries

This is a collection of Splunk queries I've made over time that can ben useful for anyone. As time goes on I'll continue to add to this.

### Carbon Black bypass  
```Processing
sourcetype=wineventlog source="WinEventLog:Application" SourceName=CbDefense Message=*Bypass*
| eval Messages = case(LIKE(Message, "%ExitBypass%"), "now Protecting",
                       LIKE(Message, "%EnterBypass%"), "no longer protecting")
| table ComputerName SourceName Messages
```
<br />

### Palo Alto GlobalProtect Private IP address
```
user=* sourcetype=pan:globalprotect (stage=connected OR stage=logout)
| table user stage private_ip machine_name
| stats latest by user
```
<br />

### Palo Alto GlobalProtect Pre-Logon IP address
```
user=pre-logon sourcetype=pan:globalprotect (stage=host-info OR stage=logout) 
| table user private_ip machine_name stage 
| eval ConnectionStatus=case(stage="host-info","Connected",stage="logout","No Longer Connected") 
| table machine_name,private_ip,user,ConnectionStatus 
| stats latest by machine_name
```
<br />

### AD user account creation|deletion|enabled|disabled
```
EventCode=4720 OR EventCode=4722 OR EventCode=4725 OR EventCode=4726 sourcetype=WinEventLog source=WinEventLog:Security 
| eval target=coalesce(Target_Account_Name,SAM_Account_Name)
| eval domain=coalesce(Target_Account_Domain,New_Account_Domain)
| table host Subject_Security_ID domain target name _time
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
