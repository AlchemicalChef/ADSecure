# Active Directory Tier Model - Admin Account Management Guide

## Overview

This guide explains how to properly create and manage tier-specific administrative accounts with appropriate security controls and lockout protection.

## Admin Account Naming Convention

Use a consistent naming convention to identify tier membership:

| Account Type | Format | Example | Description |
|-------------|---------|---------|-------------|
| **Tier 0 Admin** | `username-t0` | `john.doe-t0` | Domain controllers, core infrastructure |
| **Tier 1 Admin** | `username-t1` | `john.doe-t1` | Server management, applications |
| **Tier 2 Admin** | `username-t2` | `john.doe-t2` | Workstation management, help desk |
| **Regular User** | `username` | `john.doe` | Standard user account |

---

## Creating Tier Admin Accounts

### Tier 0 Administrator Account

```powershell
# Create Tier 0 admin account with maximum security
New-ADTierAdminAccount `
    -Username "john.doe-t0" `
    -TierName Tier0 `
    -FirstName "John" `
    -LastName "Doe" `
    -Email "john.doe@contoso.com" `
    -Description "Domain Controller Administrator" `
    -NoLockout

# Output includes:
# - Username: john.doe-t0
# - Initial password (save securely!)
# - Tier assignment: Tier0
# - Admin group: Tier0-Admins
# - Lockout protection: Enabled
