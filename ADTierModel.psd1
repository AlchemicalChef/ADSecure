@{
    RootModule = 'ADTierModel.psm1'
    ModuleVersion = '1.0.0'
    GUID = 'a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d'
    Author = 'AlchemicalChef'
    CompanyName = 'ADSecurityInsight'
    Copyright = 'Its an MIT License, go nuts'
    Description = 'Implements a comprehensive tiered administrative model for Active Directory environments with Tier 0 (Infrastructure), Tier 1 (Servers), and Tier 2 (Workstations) separation.'
    
    PowerShellVersion = '5.1'
    
    RequiredModules = @('ActiveDirectory')
    
    FunctionsToExport = @(
        # Initialization
        'Initialize-ADTierModel',
        'Get-ADTierConfiguration',

        # Tier 0 Detection
        'Get-ADTier0Infrastructure',
        'Test-ADTier0Placement',
        'Move-ADTier0Infrastructure',

        # Tier Management
        'New-ADTier',
        'Get-ADTier',
        'Set-ADTierMember',
        'Remove-ADTierMember',
        'Get-ADTierMember',

        # OU Management
        'New-ADTierOUStructure',
        'Get-ADTierOUStructure',

        # Group Management
        'New-ADTierGroup',
        'Get-ADTierGroup',
        'Add-ADTierGroupMember',
        'Remove-ADTierGroupMember',

        # Permission Management
        'Set-ADTierPermission',
        'Get-ADTierPermission',
        'Test-ADTierPermissionCompliance',

        # Auditing and Monitoring
        'Get-ADTierAccessReport',
        'Get-ADTierViolation',
        'Test-ADTierCompliance',
        'Export-ADTierAuditLog',

        # Security Policies
        'Set-ADTierAuthenticationPolicy',
        'Get-ADTierAuthenticationPolicy',
        'Set-ADTierPasswordPolicy',

        # Logon Restrictions
        'Set-ADTierLogonRestrictions',
        'Get-ADTierLogonRestrictions',
        'Test-ADTierLogonRestrictions',
        'Get-GPOLinks',
        'Set-GPOUserRight',

        # Admin Account Management
        'New-ADTierAdminAccount',
        'Set-ADTierAccountLockoutProtection',
        'Get-ADTierAdminAccount',

        # Enhanced Security Policies
        'Set-ADTierSecurityPolicy',
        'Set-GPOSecurityOption',
        'Set-GPOAuditPolicy',
        'Set-GPOFirewall',
        'Set-GPORegistryValue',

        # Cross-Tier Detection
        'Find-ADCrossTierAccess',
        'Find-ADTierMisconfiguration',
        'Repair-ADTierViolation'
    )
    
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    
    PrivateData = @{
        PSData = @{
            Tags = @('ActiveDirectory', 'Security', 'TierModel', 'Administration', 'ESAE')
            ProjectUri = 'https://github.com/AlchemicalChef/ADSecure/'
            LicenseUri = 'https://github.com/AlchemicalChef/ADSecure/'
            ReleaseNotes = 'Initial release of AD Tier Model implementation'
        }
    }
}
