param(
  [switch]$Commit
)

# >>>>>> EDIT THESE TWO LINES <<<<<<
$TargetUserUpn     = "brennan.basinger@quantinuum.com"
$TemplateUsersUpn  = @("denisse.lopez@quantinuum.com","jacob.underwood@quantinuum.com")
# >>>>>> EDIT ABOVE <<<<<<

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $here 'Mirror-M365-Access.psm1') -Force

# Load exclusions
$cfgPath = Join-Path $here 'config\Exclusions.psd1'
if (-not (Test-Path $cfgPath)) { throw "Missing config file: $cfgPath" }
$cfg = Import-PowerShellDataFile $cfgPath

# Ensure modules + connect
Ensure-Module -Name Microsoft.Graph -MinVersion "2.11.0"
Ensure-Module -Name ExchangeOnlineManagement -MinVersion "3.4.0"

if (-not (Get-MgContext)) {
  $scopes = @("User.Read.All","Group.Read.All","Group.ReadWrite.All","Directory.ReadWrite.All")
  Connect-MgGraph -Scopes $scopes
}

try { $null = Get-ConnectionInformation -ErrorAction Stop } catch { Connect-ExchangeOnline -ShowBanner:$false }

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$csv = Join-Path $here ("Mirror-Report-{0}.csv" -f $stamp)

Write-Host "Running Access Mirror (Mode=Union, Commit=$Commit) ..." -ForegroundColor Cyan

Mirror-M365-Access `
  -TargetUserUpn $TargetUserUpn `
  -TemplateUsersUpn $TemplateUsersUpn `
  -Mode Union `
  -ExcludeGroupNames $cfg.ExcludeGroupNames `
  -ExcludeGroupIds $cfg.ExcludeGroupIds `
  -ExcludeGroupNamePatterns $cfg.ExcludeGroupNamePatterns `
  -SkipSecurityGroups:($cfg.SkipSecurityGroups) `
  -SkipM365Groups:($cfg.SkipM365Groups) `
  -SkipDistributionGroups:($cfg.SkipDistributionGroups) `
  -ExportCsvPath $csv `
  -Commit:([bool]$Commit)

Write-Host "`nCSV report saved to: $csv" -ForegroundColor Green
