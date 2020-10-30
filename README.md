# CB-Cloud-Bazar-Queries
Some hunting queries you can use. Inspired by a blog by Red Canary (https://redcanary.com/blog/how-one-hospital-thwarted-a-ryuk-ransomware-outbreak/) and https://github.com/gmellini/Microsoft-Defender-Security-Center-Hunting-Queries
## Detection Opportunity #1 - Process Hollowing of cmd.exe
```((process_name:cmd.exe NOT process_cmdline:* AND netconn_count:[1 TO *]))```
## Detection Opportunity #2 - Detection Opportunity 2: Enumerating domain trusts activity with nltest.exe
```((process_name:nltest.exe AND process_cmdline:domain_trusts OR process_cmdline:all_trusts))```
## Detection Opportunity #3 - Detection Opportunity 3: Enumerating domain admins with net group
```(process_name:net.exe AND (process_cmdline:net\ \ group\ \"domain\ admins\"\ \/dom*))```
## Detection Opportunity 4: Process hollowing of explorer.exe
```(process_name:svchost.exe NOT parent_name:services.exe)
(process_name:svchost.exe AND parent_name:explorer.exe)
(process_name:svchost.exe NOT process_cmdline:*)
(process_name:svchost.exe NOT process_cmdline:"-k)"```
## Detection Opportunity 5: Attempted lateral movement via WMI + PowerShell + Cobalt Strike
