# Active Directory Tier Model - Logon Restrictions

## Overview

The AD Tier Model enforces security boundaries through **Group Policy-based logon restrictions**. These restrictions implement the core principle: **Authentication must NEVER flow downward**.

This prevents credential theft and lateral movement attacks by ensuring that high-privilege accounts cannot authenticate to lower-tier systems where they could be compromised.

---

## How Logon Restrictions Work

### The Enforcement Mechanism

When you run `Initialize-ADTierModel -CreateGPOs`, the module:

1. **Creates GPO objects** for each tier:
   - `SEC-Tier0-BasePolicy` (general settings)
   - `SEC-Tier0-LogonRestrictions` (user rights assignments)
   - `SEC-Tier1-LogonRestrictions`
   - `SEC-Tier2-LogonRestrictions`

2. **Links GPOs to tier OUs** with high priority (Order 1)

3. **Configures User Rights Assignments** via `Set-ADTierLogonRestrictions`:
   - `SeDenyInteractiveLogonRight` - Prevents console/keyboard logon
   - `SeDenyNetworkLogonRight` - Prevents network access (SMB, file shares)
   - `SeDenyRemoteInteractiveLogonRight` - Prevents RDP logon
   - `SeDenyBatchLogonRight` - Prevents scheduled task execution
   - `SeDenyServiceLogonRight` - Prevents running as Windows service

---

## Tier-Specific Restrictions

### Tier 0 (Domain Controllers & Critical Infrastructure)

**Allowed to authenticate:**
- Tier 0 admin accounts only
- Domain Admins
- Enterprise Admins

**Explicitly DENIED:**
- Tier 1 admin accounts (Tier1-Admins group)
- Tier 2 admin accounts (Tier2-Admins group)

**Why:** Tier 0 systems are the crown jewels. If a Tier 1 or Tier 2 account authenticated here, an attacker who compromised that account could steal Tier 0 credentials from memory (LSASS) and escalate to domain admin.

**GPO Applied:** `SEC-Tier0-LogonRestrictions`

```powershell
# What gets configured:
Deny Interactive Logon: CONTOSO\Tier1-Admins, CONTOSO\Tier2-Admins
Deny Network Logon: CONTOSO\Tier1-Admins, CONTOSO\Tier2-Admins
Deny Remote Interactive Logon: CONTOSO\Tier1-Admins, CONTOSO\Tier2-Admins
Deny Batch Logon: CONTOSO\Tier1-Admins, CONTOSO\Tier2-Admins
Deny Service Logon: CONTOSO\Tier1-Admins, CONTOSO\Tier2-Admins
