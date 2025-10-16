# Quantinuum Access Mirror (v2)

**What changed in v2**
- Fixed VS Code / PowerShell parsing warning by using `${gid}` inside a string (avoids `$gid:` ambiguity)
- Converted the core script into a **module** (`Mirror-M365-Access.psm1`) for clean importing moving forward
- `Start-Here.ps1` now imports the module accordingly

Everything else remains **add-only** and **union-by-default** (Denisse UNION Jacob), with exclusions and
dynamic/on-prem DL safeguards

---

# Quantinuum Access Mirror

Mirror the Microsoft 365 **group** and **distribution list** memberships to match one or more “template” users (someone who works at Quantinuum)  
**Additive only** - it **never removes** a person from any group

> **Why this works**  
> I've also included **Union Mode** for scenarios where we want “everything Denisse **or** Jacob are in” **without** removing anything we/they/(the account we are operating on) already have/has

> Use **Union** mode (the default). The script only **adds**; it **does not** remove

---

## What gets mirrored

- **Microsoft Entra groups & Microsoft 365 (Unified) groups** (example: Teams/SharePoint access)
- **Exchange Distribution Groups (DLs)** and **mail-enabled security groups** (email lists)
- **Dynamic groups/DLs** are **reported** but **not added** (membership is rules-based)

## Safety rails (best practice)

- **Add-only** changes. No removals
- **Exclusions**: configurable blocklist of group names and **wildcard patterns** (e.g., `*Admin*`, `*Privileged*`, `*BreakGlass*`, `HR-*`, `Finance-*`)
- **On‑prem/hybrid**: on-premises–synced groups/DLs are flagged and skipped (cannot be changed in the cloud)
- **Dynamic** groups/DLs are flagged and skipped (membership controlled by rules)

---

## Prerequisites

- PowerShell (x64) PS 7+ recommended
- Network egress to Microsoft 365 endpoints
- Permissions sufficient to read and update group/DL membership:
  - Microsoft Graph delegated scopes: `User.Read.All`, `Group.Read.All`, `Group.ReadWrite.All`, `Directory.ReadWrite.All` (prompted interactively)
  - Exchange Online: permission to add members to distribution groups you target

> **No RSAT needed** for cloud‑managed groups/DLs
> If the report shows items as *OnPremSynced*, those must be handled in on‑prem AD

---

## Quick start (Denisse + Jacob += John.Doe@quantinuum.com)

1. Open an elevated **PowerShell (x64)** window
2. Unzip this package somewhere, like `C:\Tools\Quantinuum-Access-Mirror`
3. Edit **`Start-Here.ps1`** and set:
   - `$TargetUserUpn = "some.one@quantinuum.com"`
   - Confirm the template users list (Denisse and Jacob are prefilled)
4. Run a **preview** (dry-run):
   ```powershell
   .\Start-Here.ps1
   ```
   This produces a CSV report in the same folder and **does not** change anything
5. When the preview looks right, **apply**:
   ```powershell
   .\Start-Here.ps1 -Commit
   ```

> **Re-run anytime**: Running it again is safe - Itonly adds what’s still missing

---

## How it decides what to add

- **Mode: `Union`** (default): Adds anything found on *either* Denisse **or** Jacob that **some.one@quantinuum.com** does not already have
- `Intersection`: Adds only what **both** have
- `First` / `Second`: Mirror just the first or second template (useful for **1 to 1** cloning)

**Nothing is ever removed** by this toolkit **EVER**

---

## Files in this package

- `Mirror-M365-Access.ps1` — core module that discovers differences, reports, and optionally applies adds
- `Start-Here.ps1` — guided entry point; reads `config/Exclusions.psd1`, connects to Graph + EXO, runs a preview or commit
- `config/Exclusions.psd1` — your organization’s exclusions and knobs

---

## Output

- Console table summarizing **WOULD ADD** / **ADD** actions
- CSV report with detailed rows: type, action, name, id, notes (dynamic/on-prem-synced/excluded/etc)

---

## Troubleshooting

- **Cannot modify members of this group because it is synchronized**: This is an on‑prem‑synced group/DL. Route to on‑prem AD
- **Dynamic group/DL**: Adjust your account attributes to match the rule (Example Department, Company) for inclusion
- **Authorization/consent prompts**: Ask Mat Woods M365 to approve the Graph scopes if consent is locked down
- **Exchange throttling**: Large tenants may take longer, re-run if needed. Preview mode helps you scope impact before applying

**Use the Preview Mode prior to applying any changes PLEASE**

---

## Support note

This toolkit is designed to be **auditable and reversible** (no deletions)
**Note** If the onboarding/offboarding pipeline already connects to Graph + EXO, we can call `Mirror-M365-Access.ps1` as a **“Clone Access (Add-Only)”** step


```powershell
# Preview
.\Start-Here.ps1

# Apply
.\Start-Here.ps1 -Commit
```
