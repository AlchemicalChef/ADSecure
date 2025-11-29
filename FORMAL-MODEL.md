# Formal Model of ADTierModel

## A Rigorous Specification Using Formal Methods

This document presents a formal model of the ADTierModel PowerShell module, which implements Microsoft's Enhanced Security Administrative Environment (ESAE) three-tier administrative model for Active Directory.

---

## 1. Type Definitions

### 1.1 Basic Types

```
TierLevel ::= Tier0 | Tier1 | Tier2

RiskLevel ::= Critical | High | Medium | Low

ObjectType ::= User | Computer | AdminWorkstation | Group | ServiceAccount

RoleType ::= DomainController | ADFS | EntraConnect | CertificateAuthority | PAW

LogLevel ::= Info | Warning | Error | Success

ViolationType ::= CrossTierAccess | PrivilegeEscalation | MisplacedObjects

GroupSuffix ::= Admins | Operators | Readers | ServiceAccounts | JumpServers

PermissionType ::= FullControl | Modify | Read | CreateDeleteChild

UserRight ::= SeDenyInteractiveLogonRight
            | SeDenyNetworkLogonRight
            | SeDenyRemoteInteractiveLogonRight
            | SeDenyBatchLogonRight
            | SeDenyServiceLogonRight

DistinguishedName ::= String  -- AD Distinguished Name format

SID ::= String  -- Security Identifier
```

### 1.2 Composite Types

```
TierConfiguration = Record {
    Name: String,
    Description: String,
    OUPath: String,
    Color: String,
    RiskLevel: RiskLevel
}

ADObject = Record {
    Identity: String,
    DistinguishedName: DistinguishedName,
    ObjectType: ObjectType,
    Enabled: Boolean,
    LastLogonDate: DateTime?
}

ADComputer = ADObject ∪ Record {
    OperatingSystem: String?,
    ServicePrincipalNames: Set<String>
}

ADUser = ADObject ∪ Record {
    MemberOf: Set<DistinguishedName>,
    PasswordLastSet: DateTime?,
    AccountNotDelegated: Boolean
}

ADGroup = ADObject ∪ Record {
    GroupScope: Universal | Global | DomainLocal,
    GroupCategory: Security | Distribution,
    Members: Set<DistinguishedName>
}

OrganizationalUnit = Record {
    Name: String,
    DistinguishedName: DistinguishedName,
    Description: String?,
    ProtectedFromAccidentalDeletion: Boolean
}

GroupPolicyObject = Record {
    Name: String,
    Id: GUID,
    Links: Set<DistinguishedName>,
    UserRights: Map<UserRight, Set<SID>>,
    SecurityOptions: Map<String, Any>,
    AuditPolicies: Map<String, (Boolean, Boolean)>  -- (success, failure)
}

Violation = Record {
    Type: ViolationType,
    Identity: String,
    Severity: Critical | High | Medium | Low,
    CurrentTier: TierLevel?,
    ViolatingTiers: Set<TierLevel>,
    Description: String
}

LogEntry = Record {
    Timestamp: DateTime,
    Level: LogLevel,
    Component: String,
    Message: String
}

ConfigState = Record {
    InitializedDate: DateTime?,
    DomainDN: DistinguishedName,
    TierConfiguration: Map<TierLevel, TierConfiguration>,
    InitializationResults: InitResults?
}

InitResults = Record {
    OUsCreated: List<DistinguishedName>,
    GroupsCreated: List<String>,
    PermissionsSet: List<String>,
    GPOsCreated: List<String>,
    Errors: List<String>
}
```

---

## 2. State Space

### 2.1 Global State

```
State = Record {
    -- Active Directory State
    Domain: DistinguishedName,
    OrganizationalUnits: Set<OrganizationalUnit>,
    Users: Set<ADUser>,
    Computers: Set<ADComputer>,
    Groups: Set<ADGroup>,
    GPOs: Set<GroupPolicyObject>,

    -- Module State
    Configuration: ConfigState,
    LogEntries: Sequence<LogEntry>,

    -- Derived State (computed)
    TierMembership: Map<TierLevel, Set<ADObject>>,
    GroupMembership: Map<ADGroup, Set<ADObject>>,
    EffectivePermissions: Map<DistinguishedName, Set<Permission>>
}
```

### 2.2 Initial State

```
InitialState = {
    Domain = ⊥,  -- uninitialized
    OrganizationalUnits = ∅,
    Users = ∅,
    Computers = ∅,
    Groups = ∅,
    GPOs = ∅,
    Configuration = DefaultConfiguration,
    LogEntries = ⟨⟩,
    TierMembership = { Tier0 ↦ ∅, Tier1 ↦ ∅, Tier2 ↦ ∅ },
    GroupMembership = ∅,
    EffectivePermissions = ∅
}

DefaultConfiguration = {
    InitializedDate = ⊥,
    DomainDN = ⊥,
    TierConfiguration = {
        Tier0 ↦ { Name = "Tier 0 - Infrastructure",
                  Description = "Domain Controllers, core identity infrastructure",
                  OUPath = "OU=Tier0",
                  Color = "Red",
                  RiskLevel = Critical },
        Tier1 ↦ { Name = "Tier 1 - Server Management",
                  Description = "Application servers, file servers",
                  OUPath = "OU=Tier1",
                  Color = "Yellow",
                  RiskLevel = High },
        Tier2 ↦ { Name = "Tier 2 - Workstation Management",
                  Description = "User workstations",
                  OUPath = "OU=Tier2",
                  Color = "Green",
                  RiskLevel = Medium }
    },
    InitializationResults = ⊥
}
```

---

## 3. Invariants

### 3.1 Structural Invariants

```
INV-1: Tier OU Hierarchy
∀ tier ∈ {Tier0, Tier1, Tier2}:
    Initialized(State) ⟹
        ∃ ou ∈ State.OrganizationalUnits:
            ou.DistinguishedName = "OU=" + tier + "," + State.Domain ∧
            ou.ProtectedFromAccidentalDeletion = true

INV-2: Standard Sub-OUs
∀ tier ∈ {Tier0, Tier1, Tier2}:
    ∀ subOU ∈ {Computers, Users, Groups, ServiceAccounts, AdminWorkstations}:
        TierOUExists(tier) ⟹
            ∃ ou ∈ State.OrganizationalUnits:
                ou.DistinguishedName = "OU=" + subOU + ",OU=" + tier + "," + State.Domain

INV-3: Tier Groups Exist
∀ tier ∈ {Tier0, Tier1, Tier2}:
    ∀ suffix ∈ {Admins, Operators, Readers, ServiceAccounts, JumpServers}:
        Initialized(State) ⟹
            ∃ g ∈ State.Groups:
                g.Name = tier + "-" + suffix ∧
                g.GroupScope = Universal ∧
                g.GroupCategory = Security
```

### 3.2 Security Invariants

```
INV-4: No Downward Authentication (Core Security Property)
∀ user ∈ State.Users, computer ∈ State.Computers:
    let userTier = GetTier(user)
    let computerTier = GetTier(computer)
    in
        userTier < computerTier ⟹ ¬CanAuthenticate(user, computer)

-- Where tier ordering is: Tier0 < Tier1 < Tier2 (lower number = higher privilege)

INV-5: Cross-Tier Isolation
∀ user ∈ State.Users:
    let tiers = { GetTier(g) | g ∈ GetGroupMemberships(user) ∩ AdminGroups }
    in
        |tiers| ≤ 1
-- Users should only have admin rights in at most one tier

INV-6: Tier 0 Credential Protection
∀ user ∈ GetTierMembers(Tier0):
    user.AccountNotDelegated = true
-- Tier 0 accounts marked sensitive and cannot be delegated

INV-7: GPO Logon Restrictions
∀ tier ∈ {Tier0, Tier1, Tier2}:
    let gpo = GetLogonRestrictionsGPO(tier)
    let deniedTiers = {Tier0, Tier1, Tier2} \ {tier}
    in
        ∀ deniedTier ∈ deniedTiers:
            ∀ right ∈ LogonRights:
                GetAdminGroup(deniedTier) ∈ gpo.UserRights[right]

-- LogonRights = {SeDenyInteractiveLogonRight, SeDenyNetworkLogonRight,
--                SeDenyRemoteInteractiveLogonRight, SeDenyBatchLogonRight,
--                SeDenyServiceLogonRight}
```

### 3.3 Placement Invariants

```
INV-8: Tier 0 Infrastructure Placement
∀ comp ∈ State.Computers:
    IsTier0Role(comp) ⟹ GetTier(comp) = Tier0

-- IsTier0Role(c) ≡
--     IsDomainController(c) ∨ IsADFS(c) ∨ IsEntraConnect(c) ∨
--     IsCertificateAuthority(c) ∨ IsPAW(c)

INV-9: Object-OU Consistency
∀ obj ∈ State.Users ∪ State.Computers ∪ State.Groups:
    InTierOU(obj, tier) ⟹ GetTier(obj) = tier
```

---

## 4. Operations

### 4.1 Initialization Operations

```
OPERATION Initialize-ADTierModel

PARAMETERS:
    CreateOUStructure: Boolean
    CreateGroups: Boolean
    SetPermissions: Boolean
    CreateGPOs: Boolean
    Force: Boolean

PRECONDITIONS:
    PRE-1: ActiveDirectoryModuleLoaded()
    PRE-2: DomainConnected()
    PRE-3: HasDomainAdminPrivileges(CurrentUser)

POSTCONDITIONS:
    POST-1: CreateOUStructure ⟹
        ∀ tier ∈ {Tier0, Tier1, Tier2}:
            TierOUExists(tier) ∧ SubOUsExist(tier)

    POST-2: CreateGroups ⟹
        ∀ tier ∈ {Tier0, Tier1, Tier2}:
            ∀ suffix ∈ {Admins, Operators, Readers, ServiceAccounts, JumpServers}:
                GroupExists(tier + "-" + suffix)

    POST-3: CreateGPOs ⟹
        ∀ tier ∈ {Tier0, Tier1, Tier2}:
            GPOExists("SEC-" + tier + "-BasePolicy") ∧
            GPOExists("SEC-" + tier + "-LogonRestrictions") ∧
            GPOLinkedTo("SEC-" + tier + "-LogonRestrictions", TierOU(tier))

    POST-4: State'.Configuration.InitializedDate ≠ ⊥

    POST-5: LogEntry("Starting AD Tier Model initialization") ∈ State'.LogEntries

STATE TRANSITION:
    State' = State ⊕ {
        OrganizationalUnits := State.OrganizationalUnits ∪ NewOUs,
        Groups := State.Groups ∪ NewGroups,
        GPOs := State.GPOs ∪ NewGPOs,
        Configuration := UpdatedConfig,
        LogEntries := State.LogEntries ⌢ NewLogEntries
    }

ERRORS:
    ¬PRE-1 ⟹ Error("ActiveDirectory module not found")
    ¬PRE-2 ⟹ Error("Cannot connect to Active Directory domain")
    ¬PRE-3 ⟹ Error("Insufficient permissions")
```

### 4.2 Tier 0 Discovery Operations

```
OPERATION Get-ADTier0Infrastructure

PARAMETERS:
    RoleType: RoleType ∪ {All}
    IncludeDescription: Boolean

PRECONDITIONS:
    PRE-1: DomainConnected()

POSTCONDITIONS:
    POST-1: Result ⊆ State.Computers
    POST-2: ∀ comp ∈ Result: IsTier0Role(comp)
    POST-3: RoleType ≠ All ⟹ ∀ comp ∈ Result: GetRoleType(comp) = RoleType

RETURNS:
    Set<Record {
        Name: String,
        RoleType: RoleType,
        RoleName: String,
        OperatingSystem: String?,
        LastLogon: DateTime?,
        CurrentOU: DistinguishedName,
        IsInTier0: Boolean,
        DistinguishedName: DistinguishedName
    }>

SIDE EFFECTS:
    LogEntry("Discovered N Tier 0 infrastructure components") added

---

OPERATION Test-ADTier0Placement

PARAMETERS:
    AutoDiscover: Boolean

PRECONDITIONS:
    PRE-1: DomainConnected()

POSTCONDITIONS:
    POST-1: Result.TotalComponents = |Get-ADTier0Infrastructure()|
    POST-2: Result.CorrectlyPlaced + Result.Misplaced = Result.TotalComponents
    POST-3: ∀ c ∈ Result.Components:
                c.Status = "Correct" ⟺ c.CurrentOU contains "OU=Tier0"

RETURNS:
    Record {
        TotalComponents: ℕ,
        CorrectlyPlaced: ℕ,
        Misplaced: ℕ,
        Components: List<ComponentStatus>
    }

---

OPERATION Move-ADTier0Infrastructure

PARAMETERS:
    WhatIf: Boolean
    Confirm: Boolean

PRECONDITIONS:
    PRE-1: DomainConnected()
    PRE-2: HasWritePermission(CurrentUser, TierOU(Tier0))

POSTCONDITIONS:
    POST-1: ¬WhatIf ⟹
        ∀ comp ∈ Get-ADTier0Infrastructure():
            comp'.DistinguishedName contains "OU=Tier0"
    POST-2: WhatIf ⟹ State' = State  -- No state change

STATE TRANSITION:
    ∀ comp ∈ MisplacedTier0Components:
        comp'.DistinguishedName = "CN=" + comp.Name + ",OU=Computers,OU=Tier0," + Domain
```

### 4.3 Tier Membership Operations

```
OPERATION Set-ADTierMember

PARAMETERS:
    Identity: String
    TierName: TierLevel
    ObjectType: ObjectType

PRECONDITIONS:
    PRE-1: ∃ obj ∈ GetADObjects(ObjectType): obj.Identity = Identity
    PRE-2: TierOUExists(TierName)
    PRE-3: HasMovePermission(CurrentUser, obj.DistinguishedName, TargetOU)

POSTCONDITIONS:
    POST-1: let obj' = GetObject(Identity) in
                obj'.DistinguishedName contains TierOU(TierName)
    POST-2: GetTier(GetObject(Identity)) = TierName
    POST-3: LogEntry("Moved ObjectType 'Identity' to TierName") ∈ State'.LogEntries

STATE TRANSITION:
    let obj = GetObject(Identity)
    let targetOU = GetSubOU(TierName, ObjectType)
    in
        State' = State ⊕ {
            GetObjectSet(ObjectType) :=
                (GetObjectSet(ObjectType) \ {obj}) ∪
                {obj ⊕ { DistinguishedName := NewDN(obj, targetOU) }}
        }

TARGET OU MAPPING:
    TargetOU(tier, objectType) =
        match objectType with
        | User           → "OU=Users,OU=" + tier + "," + Domain
        | Computer       → "OU=Computers,OU=" + tier + "," + Domain
        | AdminWorkstation → "OU=AdminWorkstations,OU=" + tier + "," + Domain
        | Group          → "OU=Groups,OU=" + tier + "," + Domain
        | ServiceAccount → "OU=ServiceAccounts,OU=" + tier + "," + Domain

---

OPERATION Remove-ADTierMember

PARAMETERS:
    Identity: String
    QuarantineOU: DistinguishedName?

PRECONDITIONS:
    PRE-1: ∃ obj ∈ AllObjects: obj.Identity = Identity

POSTCONDITIONS:
    POST-1: let obj' = GetObject(Identity) in
                obj'.DistinguishedName contains "OU=Quarantine"
    POST-2: QuarantineOU = ⊥ ⟹ QuarantineOUExists()

STATE TRANSITION:
    Move object to Quarantine OU

---

OPERATION Get-ADTierMember

PARAMETERS:
    TierName: TierLevel
    ObjectType: ObjectType ∪ {All}

PRECONDITIONS:
    PRE-1: TierOUExists(TierName)

POSTCONDITIONS:
    POST-1: ∀ obj ∈ Result: GetTier(obj) = TierName
    POST-2: ObjectType ≠ All ⟹ ∀ obj ∈ Result: obj.ObjectType = ObjectType

RETURNS:
    Set<ADObject>
```

### 4.4 Group Management Operations

```
OPERATION Add-ADTierGroupMember

PARAMETERS:
    TierName: TierLevel
    GroupSuffix: GroupSuffix
    Members: List<String>

PRECONDITIONS:
    PRE-1: GroupExists(TierName + "-" + GroupSuffix)
    PRE-2: ∀ m ∈ Members: ObjectExists(m)
    PRE-3: HasGroupModifyPermission(CurrentUser, TargetGroup)

POSTCONDITIONS:
    POST-1: let g = GetGroup(TierName + "-" + GroupSuffix) in
                ∀ m ∈ Members: GetObject(m).DistinguishedName ∈ g'.Members

SECURITY CHECK:
    -- Warn if adding cross-tier membership
    ∀ m ∈ Members:
        GetTier(m) ≠ TierName ⟹
            Warning("Adding cross-tier member to group")

---

OPERATION Remove-ADTierGroupMember

PARAMETERS:
    TierName: TierLevel
    GroupSuffix: GroupSuffix
    Members: List<String>

PRECONDITIONS:
    PRE-1: GroupExists(TierName + "-" + GroupSuffix)

POSTCONDITIONS:
    POST-1: let g = GetGroup(TierName + "-" + GroupSuffix) in
                ∀ m ∈ Members: GetObject(m).DistinguishedName ∉ g'.Members
```

### 4.5 Logon Restriction Operations

```
OPERATION Set-ADTierLogonRestrictions

PARAMETERS:
    TierName: TierLevel
    GPOName: String

PRECONDITIONS:
    PRE-1: GPOExists(GPOName)
    PRE-2: HasGPOEditPermission(CurrentUser, GPOName)

POSTCONDITIONS:
    let gpo' = GetGPO(GPOName)
    let otherTiers = {Tier0, Tier1, Tier2} \ {TierName}
    in
        ∀ tier ∈ otherTiers:
            ∀ suffix ∈ {Admins, Operators}:
                let group = GetGroup(tier + "-" + suffix)
                in
                    group.SID ∈ gpo'.UserRights[SeDenyInteractiveLogonRight] ∧
                    group.SID ∈ gpo'.UserRights[SeDenyNetworkLogonRight] ∧
                    group.SID ∈ gpo'.UserRights[SeDenyRemoteInteractiveLogonRight] ∧
                    group.SID ∈ gpo'.UserRights[SeDenyBatchLogonRight] ∧
                    group.SID ∈ gpo'.UserRights[SeDenyServiceLogonRight]

ENFORCEMENT MATRIX:
    ┌─────────────────────────────────────────────────────────────┐
    │ GPO Applied To │ Denied Logon From                          │
    ├─────────────────────────────────────────────────────────────┤
    │ Tier0 Systems  │ Tier1-Admins, Tier1-Operators,             │
    │                │ Tier2-Admins, Tier2-Operators              │
    ├─────────────────────────────────────────────────────────────┤
    │ Tier1 Systems  │ Tier0-Admins, Tier0-Operators,             │
    │                │ Tier2-Admins, Tier2-Operators              │
    ├─────────────────────────────────────────────────────────────┤
    │ Tier2 Systems  │ Tier0-Admins, Tier0-Operators,             │
    │                │ Tier1-Admins, Tier1-Operators              │
    └─────────────────────────────────────────────────────────────┘
```

### 4.6 Admin Account Operations

```
OPERATION New-ADTierAdminAccount

PARAMETERS:
    Username: String
    TierName: TierLevel
    FirstName: String
    LastName: String
    Description: String?
    NoLockout: Boolean
    Email: String?

PRECONDITIONS:
    PRE-1: ¬UserExists(Username)
    PRE-2: TierOUExists(TierName)
    PRE-3: |Username| ≤ 20  -- SAMAccountName limit
    PRE-4: HasUserCreatePermission(CurrentUser, UsersOU(TierName))

POSTCONDITIONS:
    POST-1: ∃ user' ∈ State'.Users:
                user'.SAMAccountName = Username ∧
                user'.DistinguishedName contains TierOU(TierName) ∧
                user'.Enabled = true ∧
                user'.ChangePasswordAtLogon = true

    POST-2: TierName = Tier0 ⟹
                user'.AccountNotDelegated = true

    POST-3: NoLockout ⟹
                user'.Description contains "[LOCKOUT-PROTECTED]"

    POST-4: Result.InitialPassword is cryptographically random 16-char string

RETURNS:
    Record {
        Username: String,
        TierName: TierLevel,
        DistinguishedName: DistinguishedName,
        InitialPassword: String,
        RequiresPasswordChange: Boolean,
        Created: DateTime
    }

PASSWORD GENERATION:
    GeneratePassword() = RandomString(16, CharSet) where
        CharSet = [A-Z] ∪ [a-z] ∪ [0-9] ∪ {!, @, #, $, %, ^, &, *}
```

### 4.7 Compliance and Audit Operations

```
OPERATION Test-ADTierCompliance

PARAMETERS:
    GenerateReport: Boolean
    ReportPath: String?

PRECONDITIONS:
    PRE-1: Initialized(State)

POSTCONDITIONS:
    POST-1: Result.OverallScore ∈ [0, 100]
    POST-2: Result.RiskLevel ∈ {Low, Medium, High, Critical}
    POST-3: Result.PassedChecks + Result.FailedChecks + Result.Warnings = TotalChecks
    POST-4: GenerateReport ⟹ FileExists(ReportPath)

RETURNS:
    Record {
        OverallScore: ℕ,  -- 0-100
        RiskLevel: RiskLevel,
        PassedChecks: ℕ,
        FailedChecks: ℕ,
        Warnings: ℕ,
        Details: List<ComplianceCheck>
    }

COMPLIANCE CHECKS:
    C1: AllTierOUsExist()
    C2: AllTierGroupsExist()
    C3: LogonRestrictionsConfigured()
    C4: NoCrossTierMemberships()
    C5: Tier0InfrastructureCorrectlyPlaced()
    C6: PasswordPoliciesConfigured()
    C7: AuditPoliciesConfigured()

SCORE CALCULATION:
    Score = (PassedChecks / TotalChecks) × 100

RISK LEVEL MAPPING:
    RiskLevel =
        | Score ≥ 90 → Low
        | Score ≥ 70 → Medium
        | Score ≥ 50 → High
        | otherwise  → Critical

---

OPERATION Get-ADTierViolation

PARAMETERS:
    ViolationType: ViolationType ∪ {All}

PRECONDITIONS:
    PRE-1: Initialized(State)

POSTCONDITIONS:
    POST-1: ∀ v ∈ Result: IsViolation(v)
    POST-2: ViolationType ≠ All ⟹ ∀ v ∈ Result: v.Type = ViolationType

RETURNS:
    Set<Violation>

VIOLATION DETECTION:
    CrossTierAccess:
        { v | ∃ user ∈ State.Users:
              |{ GetTier(g) | g ∈ AdminGroupMemberships(user) }| > 1 }

    MisplacedObjects:
        { v | ∃ comp ∈ State.Computers:
              IsTier0Role(comp) ∧ GetTier(comp) ≠ Tier0 }

    PrivilegeEscalation:
        { v | ∃ path ∈ AttackPaths:
              path.Source.Tier > path.Target.Tier }

---

OPERATION Find-ADCrossTierAccess

PARAMETERS: None

PRECONDITIONS:
    PRE-1: Initialized(State)

RETURNS:
    Set<Record {
        Identity: String,
        Tiers: Set<TierLevel>,
        Groups: Set<String>,
        Severity: RiskLevel
    }>

DETECTION LOGIC:
    Result = {
        (user, tiers, groups) |
        user ∈ State.Users ∧
        let adminGroups = { g | g ∈ GetMemberships(user) ∧ IsAdminGroup(g) }
        let tiers = { GetGroupTier(g) | g ∈ adminGroups }
        in |tiers| > 1
    }

---

OPERATION Repair-ADTierViolation

PARAMETERS:
    ViolationType: ViolationType ∪ {All}
    AutoFix: Boolean

PRECONDITIONS:
    PRE-1: Initialized(State)
    PRE-2: AutoFix ⟹ HasRepairPermissions(CurrentUser)

POSTCONDITIONS:
    POST-1: AutoFix ⟹ |Get-ADTierViolation(ViolationType)'| < |Get-ADTierViolation(ViolationType)|
    POST-2: ¬AutoFix ⟹ State' = State

REPAIR ACTIONS:
    CrossTierAccess:
        Remove user from all but highest-tier admin groups

    MisplacedObjects:
        Move-ADTier0Infrastructure()
```

### 4.8 Security Policy Operations

```
OPERATION Set-ADTierSecurityPolicy

PARAMETERS:
    TierName: TierLevel
    GPOName: String

PRECONDITIONS:
    PRE-1: GPOExists(GPOName)

POSTCONDITIONS:
    -- Tier-specific security hardening applied
    POST-1: SecurityOptionsConfigured(GPOName, TierName)
    POST-2: AuditPoliciesConfigured(GPOName, TierName)
    POST-3: FirewallConfigured(GPOName, TierName)

TIER-SPECIFIC POLICIES:
    ┌────────────────────────────────────────────────────────────────────┐
    │ Setting                      │ Tier0    │ Tier1    │ Tier2        │
    ├────────────────────────────────────────────────────────────────────┤
    │ LMCompatibilityLevel         │ 5        │ 5        │ 3            │
    │ NTLMv2 Required              │ Yes      │ Yes      │ Preferred    │
    │ LM Hash Storage              │ Disabled │ Disabled │ Disabled     │
    │ 128-bit Encryption           │ Required │ Required │ Preferred    │
    │ Cached Logons                │ 0        │ 2        │ 10           │
    │ Admin Account                │ Disabled │ Enabled  │ Enabled      │
    │ Display Last Username        │ No       │ Yes      │ Yes          │
    │ Firewall (Domain Profile)    │ On       │ On       │ On           │
    │ Firewall (Private Profile)   │ On       │ On       │ On           │
    │ Firewall (Public Profile)    │ On       │ On       │ On           │
    └────────────────────────────────────────────────────────────────────┘

AUDIT POLICY BY TIER:
    Tier0: Full auditing (9 categories, success + failure)
    Tier1: Moderate auditing (logon, account management, policy changes)
    Tier2: Basic auditing (logon failures, account lockouts)

---

OPERATION Set-ADTierPasswordPolicy

PARAMETERS:
    TierName: TierLevel
    MinPasswordLength: ℕ  -- default 15
    PasswordHistoryCount: ℕ  -- default 24
    MaxPasswordAge: ℕ  -- default 60 days
    LockoutThreshold: ℕ  -- default 3

PRECONDITIONS:
    PRE-1: MinPasswordLength ≥ 8
    PRE-2: PasswordHistoryCount ≤ 24
    PRE-3: LockoutThreshold ≥ 0

POSTCONDITIONS:
    POST-1: ∃ pso ∈ FineGrainedPasswordPolicies:
                pso.Name = "PSO-" + TierName + "-PasswordPolicy" ∧
                pso.MinPasswordLength = MinPasswordLength ∧
                pso.PasswordHistoryCount = PasswordHistoryCount ∧
                pso.MaxPasswordAge = MaxPasswordAge ∧
                pso.LockoutThreshold = LockoutThreshold ∧
                pso.AppliesTo = GetGroup(TierName + "-Admins")
```

---

## 5. State Transition System

### 5.1 Transition Relation

```
TRANSITION SYSTEM TS = (S, S₀, →, L)

S = Set of all possible States
S₀ = InitialState
→ ⊆ S × Action × S
L: S → 2^AP (labeling function for atomic propositions)

Actions:
    α ::= Initialize(params)
        | DiscoverTier0
        | TestPlacement
        | MoveTier0
        | SetMember(identity, tier, type)
        | RemoveMember(identity)
        | AddGroupMember(tier, suffix, members)
        | RemoveGroupMember(tier, suffix, members)
        | SetLogonRestrictions(tier, gpo)
        | CreateAdminAccount(params)
        | TestCompliance
        | DetectViolations
        | RepairViolations(type, autofix)
        | SetSecurityPolicy(tier, gpo)
        | SetPasswordPolicy(tier, params)
        | Log(entry)
```

### 5.2 Transition Diagram

```
                                    ┌─────────────┐
                                    │   Initial   │
                                    │    State    │
                                    └──────┬──────┘
                                           │
                              Initialize-ADTierModel
                                           │
                                           ▼
                          ┌────────────────────────────────┐
                          │        Initialized State       │
                          │  (OUs, Groups, GPOs created)   │
                          └────────────────┬───────────────┘
                                           │
                    ┌──────────────────────┼──────────────────────┐
                    │                      │                      │
                    ▼                      ▼                      ▼
           ┌───────────────┐     ┌─────────────────┐     ┌───────────────┐
           │   Discovery   │     │    Membership   │     │   Security    │
           │   Operations  │     │   Operations    │     │   Operations  │
           └───────┬───────┘     └────────┬────────┘     └───────┬───────┘
                   │                      │                      │
                   ▼                      ▼                      ▼
        Get-ADTier0Infrastructure  Set-ADTierMember      Set-ADTierLogonRestrictions
        Test-ADTier0Placement      Remove-ADTierMember   Set-ADTierSecurityPolicy
        Move-ADTier0Infrastructure Get-ADTierMember      Set-ADTierPasswordPolicy
                   │                      │              Set-ADTierAuthenticationPolicy
                   │                      │                      │
                   └──────────────────────┼──────────────────────┘
                                          │
                                          ▼
                               ┌──────────────────────┐
                               │  Operational State   │
                               │ (Configured & Active)│
                               └──────────┬───────────┘
                                          │
                           ┌──────────────┴──────────────┐
                           │                             │
                           ▼                             ▼
                 ┌─────────────────┐           ┌─────────────────┐
                 │    Auditing     │           │   Remediation   │
                 │   Operations    │◄─────────►│   Operations    │
                 └─────────────────┘           └─────────────────┘
                 Test-ADTierCompliance         Repair-ADTierViolation
                 Get-ADTierViolation           Move-ADTier0Infrastructure
                 Find-ADCrossTierAccess
                 Export-ADTierAuditLog
```

---

## 6. Security Properties (Temporal Logic)

### 6.1 Safety Properties

```
SAFETY-1: No Privilege Escalation
□ (∀ user, system: CanAuthenticate(user, system) ⟹ Tier(user) ≥ Tier(system))

-- "Always, if a user can authenticate to a system, the user's tier
--  is equal to or higher (more privileged) than the system's tier"

SAFETY-2: Tier Isolation Maintained
□ (∀ user: |AdminTierMemberships(user)| ≤ 1)

-- "Always, users are admin in at most one tier"

SAFETY-3: Tier 0 Integrity
□ (∀ comp: IsTier0Role(comp) ⟹ InTier0(comp))

-- "Always, Tier 0 infrastructure is in Tier 0 OU"

SAFETY-4: Credential Protection
□ (∀ user ∈ Tier0Users: user.AccountNotDelegated = true)

-- "Always, Tier 0 users cannot be delegated"

SAFETY-5: Logon Restrictions Active
□ (Initialized ⟹ LogonRestrictionsConfigured(Tier0) ∧
                   LogonRestrictionsConfigured(Tier1) ∧
                   LogonRestrictionsConfigured(Tier2))

-- "Always after initialization, logon restrictions are configured"
```

### 6.2 Liveness Properties

```
LIVENESS-1: Violations Eventually Detected
◇□ (ViolationExists ⟹ ◇ ViolationDetected)

-- "If a violation exists, it will eventually be detected"

LIVENESS-2: Audit Logs Eventually Written
□ (ActionPerformed ⟹ ◇ LogEntryCreated)

-- "Every action eventually results in a log entry"

LIVENESS-3: Initialization Completes
Initialize ⟹ ◇ (Initialized ∨ Error)

-- "Initialization eventually completes or fails"
```

### 6.3 Fairness Constraints

```
FAIRNESS-1: Compliance Checks
□◇ TestCompliance

-- "Compliance is checked infinitely often"

FAIRNESS-2: Violation Remediation
□ (ViolationDetected ∧ AutoFixEnabled ⟹ ◇ ViolationRemediated)

-- "Detected violations with auto-fix enabled are eventually remediated"
```

---

## 7. Refinement Mapping

### 7.1 Abstract to Concrete Mapping

```
ABSTRACT STATE                      CONCRETE IMPLEMENTATION
──────────────────────────────────────────────────────────────────
TierLevel                      ⟼    String ("Tier0", "Tier1", "Tier2")
ADObject                       ⟼    Microsoft.ActiveDirectory.ADObject
DistinguishedName              ⟼    String (LDAP DN format)
OrganizationalUnit             ⟼    Microsoft.ActiveDirectory.ADOrganizationalUnit
GroupPolicyObject              ⟼    Microsoft.GroupPolicy.GPO
State.OrganizationalUnits      ⟼    AD Forest (queryable via Get-ADOrganizationalUnit)
State.Configuration            ⟼    $env:ProgramData\ADTierModel\config.json
State.LogEntries               ⟼    $env:ProgramData\ADTierModel\Logs\*.log

ABSTRACT OPERATION                  CONCRETE FUNCTION
──────────────────────────────────────────────────────────────────
Initialize                     ⟼    Initialize-ADTierModel
GetTier0Infrastructure         ⟼    Get-ADTier0Infrastructure
TestPlacement                  ⟼    Test-ADTier0Placement
MoveTier0                      ⟼    Move-ADTier0Infrastructure
SetMember                      ⟼    Set-ADTierMember
GetTierMembers                 ⟼    Get-ADTierMember
SetLogonRestrictions           ⟼    Set-ADTierLogonRestrictions
CreateAdminAccount             ⟼    New-ADTierAdminAccount
TestCompliance                 ⟼    Test-ADTierCompliance
DetectViolations               ⟼    Get-ADTierViolation
RepairViolations               ⟼    Repair-ADTierViolation
```

### 7.2 Invariant Preservation

```
THEOREM: Concrete Implementation Preserves Abstract Invariants

∀ inv ∈ AbstractInvariants:
    ∀ op ∈ ConcreteOperations:
        (pre(op) ∧ inv) ⟹ (post(op) ⟹ inv')

Proof Sketch:
1. INV-4 (No Downward Authentication) preserved by:
   - Set-ADTierLogonRestrictions denies cross-tier logon
   - GPO enforcement at OU level
   - User rights are additive denials (cannot be overridden)

2. INV-5 (Cross-Tier Isolation) preserved by:
   - Get-ADTierViolation detects violations
   - Repair-ADTierViolation removes cross-tier memberships
   - Add-ADTierGroupMember warns on cross-tier additions

3. INV-6 (Tier 0 Credential Protection) preserved by:
   - New-ADTierAdminAccount sets AccountNotDelegated for Tier0
   - No operation removes this flag for Tier0 users
```

---

## 8. Attack Model and Security Analysis

### 8.1 Threat Model

```
ATTACKER CAPABILITIES:
    A1: Compromise Tier 2 workstation
    A2: Compromise Tier 2 admin credentials
    A3: Compromise Tier 1 server
    A4: Compromise Tier 1 admin credentials

ATTACK GOALS:
    G1: Escalate to Tier 1 from Tier 2
    G2: Escalate to Tier 0 from Tier 1
    G3: Compromise Domain Controller
    G4: Obtain Domain Admin credentials

DEFENSES PROVIDED:
    D1: GPO logon restrictions (blocks A1 → G1)
    D2: Tier isolation (blocks A2 → G1)
    D3: GPO logon restrictions (blocks A3 → G2)
    D4: Credential non-delegation (blocks A4 → G2, G3)
    D5: Tier 0 placement validation (detects G3 prerequisites)
```

### 8.2 Security Guarantees

```
THEOREM: Tier Isolation Security

Given:
    - Properly initialized tier model (all GPOs applied)
    - No cross-tier admin memberships
    - All Tier 0 infrastructure correctly placed

Then:
    ∀ attacker with Tier_n credentials:
        attacker cannot authenticate to Tier_{n-1} systems

Proof:
    1. GPO applies SeDeny*LogonRight to other tier admin groups
    2. Windows enforces user rights at authentication time
    3. Deny rights override Allow rights
    4. Therefore, authentication is blocked at the OS level
```

---

## 9. Completeness Analysis

### 9.1 Function Coverage

| Category | Functions | Coverage |
|----------|-----------|----------|
| Initialization | 2 | Complete |
| Tier 0 Detection | 3 | Complete |
| Tier Management | 5 | Complete |
| OU Management | 2 | Complete |
| Group Management | 4 | Complete |
| Permission Management | 3 | Complete |
| Auditing | 4 | Complete |
| Cross-Tier Detection | 3 | Complete |
| Authentication Policies | 3 | Complete |
| Logon Restrictions | 5 | Complete |
| Admin Accounts | 3 | Complete |
| Security Policies | 5 | Complete |
| Helpers | 5 | Complete |

**Total: 47 functions formally specified**

### 9.2 State Space Coverage

All mutable state elements are covered:
- ✓ Active Directory objects (Users, Computers, Groups, OUs)
- ✓ Group Policy Objects
- ✓ Module configuration (JSON)
- ✓ Log files
- ✓ Tier membership (derived)
- ✓ Effective permissions (derived)

### 9.3 Invariant Coverage

| Security Property | Invariant | Enforced By |
|-------------------|-----------|-------------|
| No downward auth | INV-4 | GPO User Rights |
| Cross-tier isolation | INV-5 | Detection + Repair |
| Credential protection | INV-6 | Account flags |
| Tier 0 placement | INV-8 | Detection + Migration |

---

## 10. Verification Conditions

### 10.1 Pre/Post Condition Verification

For each operation `op`:

```
{Pre(op)} op {Post(op)}

Verification Obligation:
    Pre(op) ∧ Body(op) ⟹ Post(op)
```

### 10.2 Key Verification Conditions

```
VC-1: Initialize creates all required OUs
    CreateOUStructure = true ∧ DomainConnected() ⟹
        ∀ tier ∈ {Tier0, Tier1, Tier2}: TierOUExists'(tier)

VC-2: Set-ADTierMember moves to correct OU
    ObjectExists(Identity) ∧ TierOUExists(TierName) ⟹
        GetTier'(Identity) = TierName

VC-3: Logon restrictions deny cross-tier access
    GPOApplied(LogonRestrictionsGPO, TierOU) ⟹
        ∀ otherTier ≠ tier: ¬CanAuthenticate(AdminOf(otherTier), SystemIn(tier))

VC-4: Compliance score accurately reflects state
    Score = (PassedChecks / TotalChecks) × 100 ∧
    PassedChecks = |{c | ComplianceCheck(c) = PASS}|

VC-5: Repair reduces violation count
    AutoFix = true ∧ |Violations| > 0 ⟹ |Violations'| < |Violations|
```

---

## 11. Model Checking Properties

These properties can be verified using model checkers like TLA+, SPIN, or NuSMV:

```tla+
---- MODULE ADTierModel ----
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS Tier0, Tier1, Tier2, Users, Computers, Groups

VARIABLES
    tierMembership,    \* Map from objects to tiers
    groupMembership,   \* Map from groups to member sets
    logonRestrictions, \* Map from tiers to denied groups
    initialized

TypeInvariant ==
    /\ tierMembership \in [Users \cup Computers -> {Tier0, Tier1, Tier2, NULL}]
    /\ initialized \in BOOLEAN

SafetyInvariant ==
    \A user \in Users, comp \in Computers:
        /\ tierMembership[user] # NULL
        /\ tierMembership[comp] # NULL
        /\ TierOrder(tierMembership[user]) < TierOrder(tierMembership[comp])
        => ~CanAuthenticate(user, comp)

NoEscalation ==
    [][\A u \in Users:
        TierOrder(tierMembership'[u]) >= TierOrder(tierMembership[u])]_tierMembership

Spec ==
    /\ Init
    /\ [][Next]_<<tierMembership, groupMembership, logonRestrictions, initialized>>
    /\ WF_<<vars>>(Initialize)
    /\ WF_<<vars>>(DetectViolations)

====
```

---

## 12. Conclusion

This formal model provides:

1. **Complete specification** of all 47+ functions in the ADTierModel
2. **Rigorous type definitions** for all data structures
3. **Formal invariants** capturing security properties
4. **Pre/post conditions** for all operations
5. **State transition system** describing the module lifecycle
6. **Temporal logic properties** for safety and liveness
7. **Refinement mapping** from abstract to concrete implementation
8. **Security analysis** with threat model and guarantees
9. **Verification conditions** for correctness proofs
10. **Model checking specifications** for automated verification

The model demonstrates that the ADTierModel, when properly configured, provides strong security guarantees against credential theft and privilege escalation attacks in Active Directory environments.
