    Status = iff(FlowStatus_s == "A", "Allow", "Deny"),
    VM = VM_s,
    InboundBytes = InboundBytes_d,
    OutboundBytes = OutboundBytes_d,
    InboundPackets = InboundPackets_d,
    OutboundPackets = OutboundPackets_d,
    FlowType = FlowType_s,
    NSGRule = NSGRule_s

    let excludedInitiators = dynamic([]);
    AuditLogs
    | where Category =~ "RoleManagement"
    | where OperationName =~ "Add member to role"
    | where Identity != "MS-PIM" //excluding events triggered by Privileged Identity Management
    | extend
        initiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
        initiatedFromIp = tostring(InitiatedBy.user.ipAddress),
        addedRoleMember = TargetResources[0].userPrincipalName,
        displayName = TargetResources[0].displayName,
        role = replace(@'\"', @'', tostring(TargetResources[0].modifiedProperties[1].newValue))
    | where initiatedByUser !in (excludedInitiators)
    | project
        TimeGenerated,
        formatedDateUTC = format_datetime(TimeGenerated, "yyyy-MM-dd HH:mm:ss"),
        SourceSystem,
        OperationName,
        initiatedByUser,
        initiatedFromIp,
        addedRoleMember,
        role,
        displayName,
        Result

