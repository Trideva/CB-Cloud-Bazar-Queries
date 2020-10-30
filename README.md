# CB-Cloud-Bazar-Queries
Some hunting queries you can use. Inspired by Red Canary and https://github.com/gmellini/Microsoft-Defender-Security-Center-Hunting-Queries
## Detection Opportunity #1 - Process Hollowing of cmd.exe
```((process_name:cmd.exe NOT process_cmdline:* AND netconn_count:[1 TO *]))```
