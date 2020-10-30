# CB-Cloud-Bazar-Queries
Some hunting queries you can use. 
Inspired by a blog by Red Canary and @merlos1977 on Twitter. The blog [can be found here](https://redcanary.com/blog/how-one-hospital-thwarted-a-ryuk-ransomware-outbreak/) and you can find the [Microsoft Defender queries here](https://github.com/gmellini/Microsoft-Defender-Security-Center-Hunting-Queries). Your Carbon Black environment may have coverage for these already, so it's a good idea to compare with existing feeds you're subscribed to. Happy hunting!

## Detection Opportunity #1 - Process Hollowing of cmd.exe
```((process_name:cmd.exe NOT process_cmdline:* AND netconn_count:[1 TO *]))```

## Detection Opportunity #2 - Detection Opportunity 2: Enumerating domain trusts activity with nltest.exe
```((process_name:nltest.exe AND process_cmdline:domain_trusts OR process_cmdline:all_trusts))```

## Detection Opportunity #3 - Detection Opportunity 3: Enumerating domain admins with net group
```(process_name:net.exe AND (process_cmdline:net\ \ group\ \"domain\ admins\"\ \/dom*))```

## Detection Opportunity 4: Process hollowing of explorer.exe
```
(process_name:svchost.exe NOT parent_name:services.exe)
(process_name:svchost.exe AND parent_name:explorer.exe)
(process_name:svchost.exe NOT process_cmdline:*)
(process_name:svchost.exe NOT process_cmdline:"-k)"
```
Split the query up due to potential false positives in the environment. 

## Detection Opportunity 5: Attempted lateral movement via WMI + PowerShell + Cobalt Strike
```
(parent_name:wmiprvse.exe AND process_name:cmd.exe AND childproc_name:powershell.exe)
(process_name:powershell.exe AND (process_cmdline:*SUVYI* OR fileless_scriptload_cmdline:*SUVYI*))
```
See Florian Roth's [Encoded Powershell rule for more ideas](https://github.com/Neo23x0/sigma/blob/master/rules/windows/process_creation/win_susp_powershell_enc_cmd.yml)

## Detection Opportunity 6: Lateral movement via Cobalt Strike’s SMB PsExec module
```((process_name:rundll32.exe NOT process_cmdline:* AND netconn_count:[1 TO *]))```

## Detection Opportunity 7: Enumerating enterprise administrator accounts
```(process_name:net.exe AND (process_cmdline:net\ \ group\ \"enterprise\ admins\"\ \/dom*))```

## Detection Opportunity 8: Credential access using lsass from regsvr32
```
(process_name:regsvr32.exe NOT process_cmdline:*)
(process_name:regsvr32.exe AND netconn_count:[1 TO *])
