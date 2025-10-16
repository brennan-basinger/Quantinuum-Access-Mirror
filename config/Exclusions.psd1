@{
    # TODO later
    ExcludeGroupNames = @(
        'Global Administrators',
        'Privileged Access',
        'BreakGlass',
        'Security Operations',
        'HR-Confidential',
        'Payroll',
        'Finance-Confidential',
        'IT-Privileged All'
    )
    ExcludeGroupIds = @(
        # '00000000-0000-0000-0000-000000000000'
    )
    ExcludeGroupNamePatterns = @(
        '*Admin*',
        '*Privileged*',
        '*BreakGlass*',
        'Tier*',
        'HR-*',
        'Finance-*',
        'Security-*'
    )
    SkipSecurityGroups     = $false
    SkipM365Groups         = $false
    SkipDistributionGroups = $false
}
