#requires -Version 5.1
Set-StrictMode -Version Latest

function Ensure-Module {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Name,[string]$MinVersion="0.0.0")
  if (-not (Get-Module -ListAvailable -Name $Name)) {
    Write-Host "Installing module $Name..." -ForegroundColor Yellow
    Install-Module $Name -Scope CurrentUser -Force -MinimumVersion $MinVersion
  }
  Import-Module $Name -ErrorAction Stop
}

function _Resolve-GraphUser {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Upn)
  $u = Get-MgUser -UserId $Upn -Property "id,displayName,userPrincipalName,mail" -ErrorAction Stop
  [PSCustomObject]@{
    Id          = $u.Id
    UPN         = $u.UserPrincipalName
    DisplayName = $u.DisplayName
    Mail        = $u.Mail
  }
}

function _Get-GraphGroupsForUser {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$UserId)

  $groups = @()
  $memberOf = Get-MgUserMemberOf -UserId $UserId -All -ErrorAction Stop
  foreach ($obj in $memberOf) {
    try {
      $g = Get-MgGroup -GroupId $obj.Id -Property "id,displayName,mail,mailEnabled,securityEnabled,groupTypes,visibility,resourceProvisioningOptions,membershipRule,membershipRuleProcessingState,onPremisesSecurityIdentifier" -ErrorAction Stop
      if ($null -ne $g) {
        $isUnified      = ($g.GroupTypes -contains "Unified")
        $isSecurity     = [bool]($g.SecurityEnabled -and -not $isUnified)
        $isDynamic      = ($g.MembershipRuleProcessingState -eq "On" -and $g.MembershipRule)
        $isOnPremSynced = [bool]$g.OnPremisesSecurityIdentifier

        $groups += [PSCustomObject]@{
          Id               = $g.Id
          DisplayName      = $g.DisplayName
          Mail             = $g.Mail
          MailEnabled      = $g.MailEnabled
          SecurityEnabled  = $g.SecurityEnabled
          GroupTypes       = ($g.GroupTypes -join ";")
          IsUnified        = $isUnified
          IsSecurity       = $isSecurity
          IsDynamic        = $isDynamic
          IsOnPremSync     = $isOnPremSynced
        }
      }
    } catch {
      # Not a group (e.g., DirectoryRole). Ignore.
    }
  }
  $groups
}

function _Get-GraphOwnedGroupsForUser {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$UserId)
  $ids = @()
  $owned = Get-MgUserOwnedObject -UserId $UserId -All 2>$null
  foreach ($obj in $owned) { 
    try { $g = Get-MgGroup -GroupId $obj.Id -Property "id"; if ($g) { $ids += $g.Id } } catch {}
  }
  $ids | Sort-Object -Unique
}

function _Get-RecipientCore {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Identity)
  Get-EXORecipient -Identity $Identity -Properties DisplayName,PrimarySmtpAddress,ExternalDirectoryObjectId,DistinguishedName
}

function _UserIsMemberOfStaticDL {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$GroupIdentity,
    [Parameter(Mandatory)][string]$UserExternalDirectoryObjectId,
    [Parameter(Mandatory)][string]$UserPrimarySmtpAddress
  )
  try {
    $members = Get-DistributionGroupMember -Identity $GroupIdentity -ResultSize Unlimited -ErrorAction Stop
    foreach ($m in $members) {
      if ($m.ExternalDirectoryObjectId -eq $UserExternalDirectoryObjectId -or $m.PrimarySmtpAddress -eq $UserPrimarySmtpAddress) { return $true }
    }
    return $false
  } catch {
    return $false
  }
}

function _Get-DLsForUser {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Identity)

  $u = _Get-RecipientCore -Identity $Identity
  if (-not $u) { throw "EXO recipient not found: $Identity" }

  $result = @()

  # Static DLs & mail-enabled security groups
  $staticDLs = Get-DistributionGroup -ResultSize Unlimited -ErrorAction SilentlyContinue
  foreach ($g in $staticDLs) {
    $isMember = _UserIsMemberOfStaticDL -GroupIdentity $g.Identity -UserExternalDirectoryObjectId $u.ExternalDirectoryObjectId -UserPrimarySmtpAddress $u.PrimarySmtpAddress
    if ($isMember) {
      $result += [PSCustomObject]@{
        Name                          = $g.Name
        PrimarySmtpAddress            = $g.PrimarySmtpAddress
        Identity                      = $g.Identity
        IsDynamic                     = $false
        IsOnPremSync                  = [bool]$g.IsDirSynced
      }
    }
  }

  # Dynamic DLs (report only)
  try {
    $dynDLs = Get-DynamicDistributionGroup -ResultSize Unlimited -ErrorAction Stop
    foreach ($dg in $dynDLs) {
      # Preview membership for this user only
      $members = Get-Recipient -ResultSize Unlimited -RecipientPreviewFilter $dg.RecipientFilter -OrganizationalUnit $dg.RecipientContainer -ErrorAction SilentlyContinue
      $hit = $false
      foreach ($m in $members) {
        if ($m.PrimarySmtpAddress -eq $u.PrimarySmtpAddress) { $hit = $true; break }
      }
      if ($hit) {
        $result += [PSCustomObject]@{
          Name                          = $dg.Name
          PrimarySmtpAddress            = $dg.PrimarySmtpAddress
          Identity                      = $dg.Identity
          IsDynamic                     = $true
          IsOnPremSync                  = [bool]$dg.IsDirSynced
        }
      }
    }
  } catch {
    # Environments without permissions for dynamic DL preview will simply skip this section
  }

  $result | Sort-Object Identity -Unique
}

function _Apply-Exclusions {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][object[]]$Items,
    [Parameter(Mandatory)][string[]]$ExcludeNames,
    [Parameter(Mandatory)][string[]]$ExcludeIds,
    [Parameter(Mandatory)][string[]]$ExcludeNamePatterns,
    [Parameter()][string]$NameProperty = 'DisplayName',
    [Parameter()][string]$IdProperty   = 'Id'
  )

  $nameSet = @{}; foreach ($n in $ExcludeNames) { if ($n) { $nameSet[$n.ToLower()] = $true } }
  $idSet   = @{}; foreach ($i in $ExcludeIds)   { if ($i) { $idSet[$i.ToLower()]   = $true } }

  $patternMatchers = @()
  foreach ($p in $ExcludeNamePatterns) {
    if ([string]::IsNullOrWhiteSpace($p)) { continue }
    $patternMatchers += $p
  }

  $out = @()
  foreach ($item in $Items) {
    $name = [string]$item.$NameProperty
    $id   = [string]$item.$IdProperty

    $excluded = $false
    if ($nameSet.ContainsKey($name.ToLower())) { $excluded = $true }
    if ($idSet.ContainsKey($id.ToLower()))     { $excluded = $true }
    if (-not $excluded -and $patternMatchers.Count -gt 0) {
      foreach ($pat in $patternMatchers) {
        if ($name -like $pat) { $excluded = $true; break }
      }
    }
    if (-not $excluded) { $out += $item }
  }
  $out
}

function Mirror-M365-Access {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$TargetUserUpn,
    [Parameter(Mandatory)][string[]]$TemplateUsersUpn,
    [ValidateSet('Union','Intersection','First','Second')]
    [string]$Mode = 'Union',
    [switch]$CopyOwners,
    [string[]]$ExcludeGroupNames = @(),
    [string[]]$ExcludeGroupIds = @(),
    [string[]]$ExcludeGroupNamePatterns = @(),
    [switch]$SkipSecurityGroups,
    [switch]$SkipM365Groups,
    [switch]$SkipDistributionGroups,
    [switch]$Commit,
    [string]$ExportCsvPath = (Join-Path -Path (Get-Location) -ChildPath ("MirrorAccess-{0}.csv" -f (Get-Date -Format 'yyyyMMdd-HHmmss')))
  )

  # Resolve users
  $target    = _Resolve-GraphUser -Upn $TargetUserUpn
  $templates = $TemplateUsersUpn | ForEach-Object { _Resolve-GraphUser -Upn $_ }

  # Collect template memberships
  $tmplGraphGroupsAll = @()
  $tmplDLsAll         = @()
  $tmplOwnedGroupsAll = @()

  foreach ($t in $templates) {
    $tmplGraphGroupsAll += _Get-GraphGroupsForUser   -UserId $t.Id
    if (-not $SkipDistributionGroups) {
      $tmplDLsAll         += _Get-DLsForUser           -Identity ($t.Mail ? $t.Mail : $t.UPN)
    }
    $tmplOwnedGroupsAll += _Get-GraphOwnedGroupsForUser -UserId $t.Id
  }

  # Mode selection
  $tmplGraphGroups = $tmplGraphGroupsAll | Sort-Object Id -Unique
  $tmplDLs         = $tmplDLsAll         | Sort-Object Identity -Unique
  $tmplOwnedGroups = $tmplOwnedGroupsAll | Sort-Object -Unique

  switch ($Mode) {
    'Intersection' {
      $idsCommon = ($templates | ForEach-Object { _Get-GraphGroupsForUser -UserId $_.Id | Select-Object -ExpandProperty Id }) |
        Group-Object | Where-Object {$_.Count -eq $templates.Count} | Select-Object -ExpandProperty Name
      $tmplGraphGroups = $tmplGraphGroups | Where-Object { $idsCommon -contains $_.Id }

      if (-not $SkipDistributionGroups) {
        $dlCommon = ($templates | ForEach-Object { _Get-DLsForUser -Identity ($_.Mail ? $_.Mail : $_.UPN) | Select-Object -ExpandProperty Identity }) |
          Group-Object | Where-Object {$_.Count -eq $templates.Count} | Select-Object -ExpandProperty Name
        $tmplDLs = $tmplDLs | Where-Object { $dlCommon -contains $_.Identity }
      }
    }
    'First' {
      $first = $templates[0]
      $tmplGraphGroups = _Get-GraphGroupsForUser -UserId $first.Id
      if (-not $SkipDistributionGroups) {
        $tmplDLs         = _Get-DLsForUser         -Identity ($first.Mail ? $first.Mail : $first.UPN)
      }
      $tmplOwnedGroups = _Get-GraphOwnedGroupsForUser -UserId $first.Id
    }
    'Second' {
      if ($templates.Count -lt 2) { throw "Mode 'Second' requires two template users" }
      $second = $templates[1]
      $tmplGraphGroups = _Get-GraphGroupsForUser -UserId $second.Id
      if (-not $SkipDistributionGroups) {
        $tmplDLs         = _Get-DLsForUser         -Identity ($second.Mail ? $second.Mail : $second.UPN)
      }
      $tmplOwnedGroups = _Get-GraphOwnedGroupsForUser -UserId $second.Id
    }
    default { } # Union (already computed)
  }

  # Exclusions & type filters
  $tmplGraphGroups = _Apply-Exclusions -Items $tmplGraphGroups -ExcludeNames $ExcludeGroupNames -ExcludeIds $ExcludeGroupIds -ExcludeNamePatterns $ExcludeGroupNamePatterns -NameProperty 'DisplayName' -IdProperty 'Id'
  if (-not $SkipDistributionGroups) {
    $tmplDLs         = _Apply-Exclusions -Items $tmplDLs         -ExcludeNames $ExcludeGroupNames -ExcludeIds $ExcludeGroupIds -ExcludeNamePatterns $ExcludeGroupNamePatterns -NameProperty 'Name' -IdProperty 'Identity'
  }

  if ($SkipSecurityGroups) { $tmplGraphGroups = $tmplGraphGroups | Where-Object { -not $_.IsSecurity } }
  if ($SkipM365Groups)     { $tmplGraphGroups = $tmplGraphGroups | Where-Object { -not $_.IsUnified } }

  # Current target memberships
  $targetGraphGroups = _Get-GraphGroupsForUser -UserId $target.Id
  $targetDLs         = @()
  if (-not $SkipDistributionGroups) {
    $targetDLs         = _Get-DLsForUser         -Identity ($target.Mail ? $target.Mail : $target.UPN)
  }
  $targetOwnedGroups = _Get-GraphOwnedGroupsForUser -UserId $target.Id

  # Compute diffs (ADD ONLY)
  $graphToAdd = foreach ($g in $tmplGraphGroups) {
    if ($g.IsDynamic)      { $g | Add-Member NoteProperty Reason "Skipped (dynamic Entra group)" -Force; continue }
    if ($g.IsOnPremSync)   { $g | Add-Member NoteProperty Reason "Skipped (on-prem synced, change in AD)" -Force; continue }
    if ($targetGraphGroups.Id -notcontains $g.Id) { $g }
  }

  $dlToAdd = @()
  if (-not $SkipDistributionGroups) {
    foreach ($dl in $tmplDLs) {
      if ($dl.IsDynamic) {
        $dl | Add-Member NoteProperty Reason "Skipped (dynamic DL, rule-based)" -Force
        continue
      }
      if ($dl.IsOnPremSync) {
        $dl | Add-Member NoteProperty Reason "Skipped (on-prem synced, change in AD)" -Force
        continue
      }
      if ($targetDLs.Identity -notcontains $dl.Identity) { $dlToAdd += $dl }
    }
  }

  $ownersToAdd = @()
  if ($CopyOwners) {
    $ownersToAdd = $tmplOwnedGroups | Where-Object { $targetOwnedGroups -notcontains $_ }
  }

  # Report AND optionally apply
  $report = New-Object System.Collections.Generic.List[object]

  foreach ($g in $graphToAdd) {
    $report.Add([PSCustomObject]@{
      Type   = if ($g.IsUnified) { "M365 Group" } elseif ($g.IsSecurity) { "Security Group" } else { "Group" }
      Action = if ($Commit) { "ADD" } else { "WOULD ADD" }
      Name   = $g.DisplayName
      Id     = $g.Id
      Notes  = $g.PSObject.Properties.Match('Reason').Value
    })
    if ($Commit) {
      try {
        $ref = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($target.Id)" }
        New-MgGroupMemberByRef -GroupId $g.Id -BodyParameter $ref -ErrorAction Stop | Out-Null
      } catch {
        Write-Warning "Failed to add to $($g.DisplayName): $($_.Exception.Message)"
      }
    }
  }

  foreach ($dl in $dlToAdd) {
    $report.Add([PSCustomObject]@{
      Type   = "Distribution Group"
      Action = if ($Commit) { "ADD" } else { "WOULD ADD" }
      Name   = $dl.Name
      Id     = $dl.Identity
      Notes  = $dl.PSObject.Properties.Match('Reason').Value
    })
    if ($Commit) {
      try {
        Add-DistributionGroupMember -Identity $dl.Identity -Member $target.Mail -ErrorAction Stop
      } catch {
        Write-Warning "Failed to add to DL $($dl.Name): $($_.Exception.Message)"
      }
    }
  }

  if ($CopyOwners -and $ownersToAdd) {
    foreach ($gid in $ownersToAdd) {
      $report.Add([PSCustomObject]@{
        Type   = "Group Owner"
        Action = if ($Commit) { "ADD OWNER" } else { "WOULD ADD OWNER" }
        Name   = $gid
        Id     = $gid
        Notes  = ""
      })
      if ($Commit) {
        try {
          $ref = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($target.Id)" }
          New-MgGroupOwnerByRef -GroupId $gid -BodyParameter $ref -ErrorAction Stop | Out-Null
        } catch {
          Write-Warning "Failed to add owner on ${gid}: $($_.Exception.Message)"
        }
      }
    }
  }

  $report | Tee-Object -Variable _out | Format-Table -AutoSize
  if ($ExportCsvPath) {
    $_out | Export-Csv -NoTypeInformation -Path $ExportCsvPath
    Write-Host "Report exported to $ExportCsvPath" -ForegroundColor Green
  }
  Write-Host ("Completed. Target: {0}. Templates: {1}. Mode: {2}. Commit: {3}" -f $target.UPN, ($templates.UPN -join ', '), $Mode, $Commit) -ForegroundColor Cyan
}

Export-ModuleMember -Function Mirror-M365-Access,Ensure-Module
