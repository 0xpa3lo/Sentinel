        let failedEventId = "4625";
        let accountAttemptLimit = 8;
        let lookback = 1h;
        let excludedAccounts = dynamic([""]);
        SecurityEvent
        | where TimeGenerated >= ago(lookback)
        | where EventID in (failedEventId)
        | extend formattedTargetAccount = split(TargetAccount, "\\")[1][-1]
        | where formattedTargetAccount !in (excludedAccounts)
        | where isnotempty(IpAddress) and IpAddress != "-"
        | summarize
            startTime = min(TimeGenerated),
            endTime = max(TimeGenerated),
            attemptedAccounts = make_set(TargetAccount, 100),
            failedSignInAttempts = count()
            by
            IpAddress,
            Computer,
            ResourceId
        | extend attemptedAccountsCount = array_length(attemptedAccounts)
        | where attemptedAccountsCount > accountAttemptLimit
        | extend isExternalIp = iff(ipv4_is_private(IpAddress), false, true)
        | project
            startTime,
            endTime,
            attemptedAccountsCount,
            failedSignInAttempts,
            IpAddress,
            isExternalIp,
            Computer,
            attemptedAccounts,
            ResourceId
