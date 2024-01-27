  let lookback = 15m;
  let cmdIndicators = pack_array("netsh", "wlan", "show", "profile", "key=clear");
  (union isfuzzy=true
      (
          SecurityEvent
          | where TimeGenerated >= ago(lookback)
          | where EventID == 4688
          | extend
              FileName = tostring(split(NewProcessName, @'')[(-1)]),
              ProcessCommandLine = CommandLine,
              InitiatingProcessFileName = ParentProcessName,
              ProcessIdCustomEntity = toint(NewProcessId)
          | where ProcessCommandLine has_all (cmdIndicators)
          | project
              TimeGenerated,
              HostCustomEntity = Computer,
              AccountCustomEntity = Account,
              AccountDomain,
              ProcessName,
              ProcessNameFullPath = NewProcessName,
              EventID,
              Activity,
              FileName,
              ProcessCommandLine,
              ProcessIdCustomEntity,
              EventSourceName,
              Type
      ),
      (
          DeviceProcessEvents
          | where TimeGenerated >= ago(lookback)
          | where ProcessCommandLine has_all (cmdIndicators)
          | extend 
              AccountCustomEntity = AccountUpn,
              HostCustomEntity = DeviceName,
              ProcessIdCustomEntity = toint(ProcessId)
      )
  )

