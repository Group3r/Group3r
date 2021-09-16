using LibSnaffle.ActiveDirectory;
using LibSnaffle.Classifiers.Rules;
using System.Collections.Generic;

namespace Group3r.Options.AssessmentOptions
{
    public partial class AssessmentOptions
    {
        public void LoadRegKeys()
        {
            RegKeys = new List<RegKey>()
            {
                new RegKey()
                {
                    MsDesc = "",
                    FriendlyDescription = "Automatic Certificate Request Settings (ACRS) provides a method to automatically distribute certificates to Windows 2000, Windows XP, and Windows Server 2003 computers that are domain members. ACRS is useful for distributing Computer or IPSec certificates to all computers in a domain.",
                    Key = "Policies\\Microsoft\\SystemCertificates\\ACRS",
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    MsDesc = " ",
                    FriendlyDescription = "",
                    Key = "Policies\\Microsoft\\SystemCertificates\\CA\\Certificates",
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    MsDesc = " ",
                    FriendlyDescription = "",
                    Key = "Policies\\Microsoft\\SystemCertificates\\Disallowed\\Certificates",
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    MsDesc = " ",
                    FriendlyDescription = "Certificates that are used as part of the Encrypting File System process.",
                    Key = "Policies\\Microsoft\\SystemCertificates\\EFS",
                    ValueName = "",
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    MsDesc = " ",
                    FriendlyDescription = "Registry locataion of the Bitlocker Network Unlock certificate. Network Unlock was introduced as a BitLocker protector option for operating system volumes. Network Unlock helps manage BitLocker-enabled desktops and servers in a domain environment by automatically unlocking operating system volumes when the system is rebooted and is connected to a wired corporate network.",
                    Key = "Policies\\Microsoft\\SystemCertificates\\FVE_NKP\\Certificates",
                    ValueName = "",
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    MsDesc = "",
                    FriendlyDescription = "Certificate store for Full Volume Encryption (Bitlocker).",
                    Key = "Policies\\Microsoft\\SystemCertificates\\FVE\\Certificates",
                    ValueName = "",
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    MsDesc = "",
                    FriendlyDescription = "Certificate store for trusted certificate authorities (CA).",
                    Key = "Policies\\Microsoft\\SystemCertificates\\Root\\Certificates",
                    ValueName = "",
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    MsDesc = " ",
                    FriendlyDescription = "Certificate store for other trusted people and resources.",
                    Key = "Policies\\Microsoft\\SystemCertificates\\Trust\\Certificates",
                    ValueName = "",
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    MsDesc = " ",
                    FriendlyDescription = "",
                    Key = "Policies\\Microsoft\\SystemCertificates\\TrustedPeople\\Certificates",
                    ValueName = "",
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    MsDesc = "",
                    FriendlyDescription = "Certificate store for trusted application publishers.",
                    Key = "Policies\\Microsoft\\SystemCertificates\\TrustedPublisher\\Certificates",
                    ValueName = "",
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    MsDesc = "",
                    FriendlyDescription = "Keys related to Software Restriction Policies.",
                    Key = "Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers",
                    ValueName = "",
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    MsDesc = "",
                    FriendlyDescription = "AppLocker restrictions on running Universal Windows Platform (AppX) apps.",
                    Key = "Policies\\Microsoft\\Windows\\SrpV2\\Appx",
                    ValueName = "",
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    MsDesc = "",
                    FriendlyDescription = "AppLocker restrictions on running Dynamic Link Libraries (.DLL and .OCX).",
                    Key = "Policies\\Microsoft\\Windows\\SrpV2\\Exe",
                    ValueName = "",
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    MsDesc = "",
                    FriendlyDescription = "AppLocker restrictions on running Executable images (.EXE and .COM).",
                    Key = "Policies\\Microsoft\\Windows\\SrpV2\\Exe",
                    ValueName = "",
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    MsDesc = "",
                    FriendlyDescription = "AppLocker restrictions on running Microsoft Software Installer (.MSI and .MSP) for both install and uninstall.",
                    Key = "Policies\\Microsoft\\Windows\\SrpV2\\Msi",
                    ValueName = "",
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    MsDesc = "",
                    FriendlyDescription = "AppLocker restrictions on running Scripts",
                    Key = "Policies\\Microsoft\\Windows\\SrpV2\\Script",
                    ValueName = "",
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    MsDesc = "",
                    FriendlyDescription = "Location of values associated with firewall rules.",
                    Key = "Policies\\Microsoft\\WindowsFirewall\\FirewallRules",
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    MsDesc = "Local Account Token Filter Policy",
                    FriendlyDescription = "If set to 1, allows local accounts in the local Administrators group to remotely log on with an elevated token.",
                    Key = "Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                    ValueName = "LocalAccountTokenFilterPolicy",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 0,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Yellow
                },
                new RegKey()
                {
                    MsDesc = "Include command line in process creation events",
                    FriendlyDescription = "If set to 1, logs the full command line in process creation events (4688) in the event log.",
                    Key =
                        "Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit",
                    ValueName = "ProcessCreationIncludeCmdLine_Enabled",
                    DefaultDword = 0,
                    ValueType = RegKeyValType.REG_DWORD,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },
                new RegKey()
                {
                    MsDesc = "Turn off downloading of print drivers over HTTP",
                    FriendlyDescription = "Specifies whether to allow a client to download print driver packages over HTTP",
                    Key = "Policies\\Microsoft\\Windows NT\\Printers",
                    DefaultDword = 0,
                    ValueName = "DisableWebPnPDownload",
                    ValueType = RegKeyValType.REG_DWORD,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },
                new RegKey()
                {
                    MsDesc = "Enable insecure guest logons",
                    FriendlyDescription = "Permits unauthenticated/guest access to file shares.",
                    Key = "Policies\\Microsoft\\Windows\\LanmanWorkstation",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 1,
                    BadDword = 1,
                    ValueName = "AllowInsecureGuestAuth",
                    InterestingIf = InterestingIf.Bad
                },
                new RegKey()
                {
                    MsDesc = "Turn on PowerShell Script Block Logging",
                    FriendlyDescription = "If enabling PowerShell script block logging will record detailed information from the processing of PowerShell commands and scripts.",
                    Key = "Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
                    DefaultDword = 0,
                    ValueName = "EnableScriptBlockLogging",
                    ValueType = RegKeyValType.REG_DWORD,
                    InterestingIf = InterestingIf.NotDefault
                },
                new RegKey()
                {
                    MsDesc = "Allow Basic authentication (Client)",
                    FriendlyDescription = "If enabled this policy allows a WinRM client to use Basic authentication. If WinRM is configured to use HTTP transport the user name and password are sent over the network as clear text.",
                    Key = "Policies\\Microsoft\\Windows\\WinRM\\Client",
                    DefaultDword = 0,
                    ValueType = RegKeyValType.REG_DWORD,
                    InterestingIf = InterestingIf.NotDefault,
                    ValueName = "AllowBasic",
                },
                new RegKey()
                {
                    MsDesc = "Disallow Digest authentication",
                    FriendlyDescription = "If enabled this policy configures the WinRM client to not use Digest authentication.",
                    Key = "Policies\\Microsoft\\Windows\\WinRM\\Client",
                    ValueName = "AllowDigest",
                    DefaultDword = 0,
                    ValueType = RegKeyValType.REG_DWORD,
                    InterestingIf = InterestingIf.NotDefault
                },
                new RegKey()
                {
                    MsDesc = "Allow unencrypted traffic (Client)",
                    FriendlyDescription = "If enabled this policy allows the WinRM client to send and receive unencrypted messages over the network.",
                    Key = "Policies\\Microsoft\\Windows\\WinRM\\Client",
                    ValueName = "AllowUnencryptedTraffic",
                    DefaultDword = 0,
                    ValueType = RegKeyValType.REG_DWORD,
                    InterestingIf = InterestingIf.NotDefault
                },
                new RegKey()
                {
                    MsDesc = "Allow Basic authentication (Server)",
                    FriendlyDescription = "If enabled this policy allows the WinRM server to use Basic authentication from a remote client.",
                    Key = "Policies\\Microsoft\\Windows\\WinRM\\Service",
                    ValueName = "AllowBasic",
                    DefaultDword = 0,
                    ValueType = RegKeyValType.REG_DWORD,
                    InterestingIf = InterestingIf.NotDefault
                },
                new RegKey()
                {
                    MsDesc = "Allow unencrypted traffic (Server)",
                    FriendlyDescription = "If enabled this policy allows the WinRM client sends and receive unencrypted messages over the network.",
                    Key = "Policies\\Microsoft\\Windows\\WinRM\\Service",
                    ValueName = "AllowUnencryptedTraffic",
                    DefaultDword = 0,
                    ValueType = RegKeyValType.REG_DWORD,
                    InterestingIf = InterestingIf.NotDefault
                },
                new RegKey()
                {
                    MsDesc = "Disallow WinRM from storing RunAs credentials",
                    FriendlyDescription = "If enabled the WinRM service will not allow the RunAsUser or RunAsPassword configuration values to be set for any plug-ins.",
                    Key = "Policies\\Microsoft\\Windows\\WinRM\\Service",
                    ValueName = "DisableRunAs",
                    DefaultDword = 0,
                    ValueType = RegKeyValType.REG_DWORD,
                    InterestingIf = InterestingIf.NotDefault
                },
                new RegKey()
                {
                    MsDesc = "WDigest Authentication Disabled",
                    FriendlyDescription = "If set to 1, WDigest will store credentials in memory.",
                    Key = "CurrentControlSet\\Control\\SecurityProviders\\WDigest",
                    ValueName = "UseLogonCredentials",
                    DefaultDword = 0,
                    ValueType = RegKeyValType.REG_DWORD,
                    InterestingIf = InterestingIf.NotDefault
                },
                new RegKey()
                {
                    MsDesc = "WPAD Disabled",
                    FriendlyDescription = "Disables the Web Proxy Auto-Discovery (WPAD) protocol which allows for easier configuration of proxy settings for WinHTTP-based applications.",
                    Key = "CurrentControlSet\\Services\\WinHttpAutoProxySvc",
                    ValueName = "Start",
                    DefaultDword = 3,
                    ValueType = RegKeyValType.REG_DWORD,
                    InterestingIf = InterestingIf.NotDefault
                },
                new RegKey()
                {
                    MsDesc = "Devices: Prevent users from installing printer drivers",
                    FriendlyDescription = "If this setting is enabled, only Administrators can install a printer driver as part of connecting to a shared printer. If this setting is disabled, any user can install a printer driver as part of connecting to a shared printer.",
                    Key = "CurrentControlSet\\Control\\Print\\Providers\\LanMan Print Services\\Servers",
                    ValueName = "AddPrinterDrivers",
                    ValueType = RegKeyValType.REG_DWORD,
                    InterestingIf = InterestingIf.Present
                },
                new RegKey()
                {
                    MsDesc = "Turn on automatic logon in Windows: Default Password",
                    FriendlyDescription = "Allows the setting of a default password in the registry for automatic login.",
                    Key = "Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                    ValueName = "DefaultPassword",
                    InterestingIf = InterestingIf.Present
                },
                new RegKey()
                {
                    MsDesc = "Turn on automatic logon in Windows: Default Username",
                    FriendlyDescription = "Allows the setting of a default username in the registry for automatic login.",
                    Key = "Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                    ValueName = "DefaultUserName",
                    InterestingIf = InterestingIf.Present
                },
                new RegKey()
                {
                    MsDesc = "Turn on automatic logon in Windows: Automatic Admin Logon",
                    FriendlyDescription = "Allows automatic logon for Admin users.",
                    Key = "Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                    ValueName = "AutoAdminLogon",
                    InterestingIf = InterestingIf.Present
                },
                new RegKey()
                {
                    //
                    MsDesc = "Recovery console: Allow automatic administrative logon",
                    FriendlyDescription =
                        "Determines if the password for the Administrator account must be given before access to the system is granted.",
                    Key = "Software\\Microsoft\\WindowsNT\\CurrentVersion\\Setup\\RecoveryConsole",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "SecurityLevel",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 0,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Recovery console: Allow floppy copy and access to all drives and all folders",
                    FriendlyDescription =
                        "Makes the Recovery Console SET command available, which allows you to set Recovery Console environment variables.",
                    Key = "Software\\Microsoft\\WindowsNT\\CurrentVersion\\Setup\\RecoveryConsole",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "SetCommand",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 0,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc =
                        "Interactive logon: Number of previous logons to cache (in case domain controller is not available)",
                    FriendlyDescription = "Determines the number of cached logon credentials to retain locally.",
                    Key = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "CachedLogonsCount",
                    ValueType = RegKeyValType.REG_SZ,
                    InterestingIf = InterestingIf.NotDefault,
                    DefaultSz = "10",
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc =
                        "User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode",
                    FriendlyDescription =
                        "Options include Prompt for Consent (Permit or Deny), Prompt for Credentials, Elevate without prompting.",
                    Key = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "ConsentPromptBehaviorAdmin",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 5,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "User Account Control: Run all administrators in Admin Approval Mode",
                    FriendlyDescription =
                        "Determines the behavior of all User Account Control policies for the entire system.",
                    Key = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "EnableLUA",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 1,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc =
                        "User Account Control: Only elevate UIAccess applications that are installed in secure locations",
                    FriendlyDescription =
                        "Enforces the requirement that applications that request execution with a User Interface Accessibility integrity level, must reside in a secure location on the file system",
                    Key = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "EnableSecureUIAPaths",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 1,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc =
                        "User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop",
                    FriendlyDescription =
                        "Controls whether User Interface Accessibility programs can automatically disable the secure desktop for elevation prompts being used by a standard user.",
                    Key = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "EnableUIADesktopToggle",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 0,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "User Account Control: Admin Approval Mode for the built-in Administrator account",
                    FriendlyDescription =
                        "If enabled the built-in administrator will logon in Admin Approval Mode and any operation that requires elevation of privilege will prompt the Consent Admin to choose either Permit or Deny.",
                    Key = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "FilterAdministratorToken",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 0,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Interactive logon: Message title for users attempting to logon",
                    FriendlyDescription = "The legal notice displayed before logging into Windows.",
                    Key = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "LegalNoticeCaption",
                    ValueType = RegKeyValType.REG_SZ,
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Interactive logon: Message text for users attempting to logon",
                    FriendlyDescription = "Specifies a text message that is displayed to users when they log on.",
                    Key = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "LegalNoticeText",
                    ValueType = RegKeyValType.REG_MULTI_SZ,
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "User Account Control: Switch to the secure desktop when prompting for elevation",
                    FriendlyDescription =
                        "Determines whether the elevation request will prompt on the interactive users desktop or the Secure Desktop.",
                    Key = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "PromptOnSecureDesktop",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 1,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Interactive logon: Require smart card",
                    FriendlyDescription = "Requires users to log on to a computer using a smart card.",
                    Key = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "ScForceOption",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 0,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "User Account Control: Only elevate executables that are signed and validated",
                    FriendlyDescription =
                        "Enforces PKI signature checks on any interactive application that requests elevation of privilege.",
                    Key = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "ValidateAdminCodeSignatures",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 0,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "System cryptography: Force strong key protection for user keys stored on the computer",
                    FriendlyDescription = "Determines if users' private keys require a password to be used.",
                    Key = "Software\\Policies\\Microsoft\\Cryptography",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "ForceKeyProtection",
                    ValueType = RegKeyValType.REG_DWORD,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc =
                        "DCOM: Machine Access Restrictions in Security Descriptor Definition Language (SDDL) syntax",
                    FriendlyDescription =
                        "Determines which users or groups can access DCOM application remotely or locally. This setting is used to control the attack surface of the computer for DCOM applications.",
                    Key = "Software\\Policies\\Microsoft\\Windows NT\\DCOM",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "MachineAccessRestriction",
                    ValueType = RegKeyValType.REG_SZ,
                    DefaultSz = "",
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc =
                        "DCOM: Machine Launch Restrictions in Security Descriptor Definition Language (SDDL) syntax",
                    FriendlyDescription =
                        "Determines which users or groups can launch or activate DCOM applications remotely or locally. This setting is used to control the attack surface of the computer for DCOM applications.",
                    Key = "Software\\Policies\\Microsoft\\Windows NT\\DCOM",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "MachineLaunchRestriction",
                    ValueType = RegKeyValType.REG_SZ,
                    DefaultSz = "",
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc =
                        "System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies",
                    FriendlyDescription =
                        "Determines if digital certificates are processed when a user or process attempts to run software with an .exe file name extension. ",
                    Key = "Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "AuthenticodeEnabled",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 0,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Audit: Audit the access of global system objects",
                    FriendlyDescription =
                        "If enabled, it causes system objects, to be created with a default system access control list (SACL). Only named objects are given a SACL.",
                    Key = "System\\CurrentControlSet\\Control\\Lsa",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "AuditBaseObjects",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 0,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Audit: Shut down system immediately if unable to log security audits",
                    FriendlyDescription =
                        "If enabled, causes the system to stop if a security audit cannot be logged for any reason e.g. audit log is full",
                    Key = "System\\CurrentControlSet\\Control\\Lsa",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "CrashOnAuditFail",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 0,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc =
                        "Network access: Do not allow storage of passwords and credentials for network authentication",
                    FriendlyDescription =
                        "Determines whether Stored User Names and Passwords saves passwords, credentials, or .NET Passports for later use when it gains domain authentication.",
                    Key = "System\\CurrentControlSet\\Control\\Lsa",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "DisableDomainCreds",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 0,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Network access: Let Everyone permissions apply to anonymous users",
                    FriendlyDescription =
                        "Determines what additional permissions are granted for anonymous connections to the computer e.g. enumerating the names of domain accounts and network shares. ",
                    Key = "System\\CurrentControlSet\\Control\\Lsa",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "EveryoneIncludesAnonymous",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 0,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Yellow
                },

                new RegKey()
                {
                    //
                    MsDesc = "Network access: Sharing and security model for local accounts",
                    FriendlyDescription =
                        "Determines how network logons that use local accounts are authenticated. Can be set to Classic or Guest only.",
                    Key = "System\\CurrentControlSet\\Control\\Lsa",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "ForceGuest",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 0,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Audit: Audit the use of Backup and Restore privilege",
                    FriendlyDescription =
                        "Determines whether to audit the use of all user privileges, including Backup and Restore, when the Audit privilege use policy is in effect.",
                    Key = "System\\CurrentControlSet\\Control\\Lsa",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "FullPrivilegeAuditing",
                    ValueType = RegKeyValType.REG_BINARY,
                    DefaultDword = 0,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Accounts: Limit local account use of blank passwords to console logon only",
                    FriendlyDescription =
                        "Determines whether local accounts that are not password protected can be used to log on from locations other than the physical computer console. ",
                    Key = "System\\CurrentControlSet\\Control\\Lsa",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "LimitBlankPasswordUse",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 1,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Network security: LAN Manager authentication level",
                    FriendlyDescription =
                        "Determines which challenge response authentication protocol is used for network logons. This choice affects the level of authentication protocol used by clients, the level of session security negotiated, and the level of authentication accepted by servers.",
                    Key = "System\\CurrentControlSet\\Control\\Lsa",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "LmCompatibilityLevel",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 3,
                    InterestingIf = InterestingIf.NotGood,
                    GoodDword = 5,
                    Triage = Constants.Triage.Yellow
                },

                new RegKey()
                {
                    //
                    MsDesc = "Network security: Allow LocalSystem NULL session fallback",
                    FriendlyDescription = "Allow NTLM to fall back to NULL session when used with LocalSystem.",
                    Key = "System\\CurrentControlSet\\Control\\Lsa\\MSV1_0",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "allownullsessionfallback",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 0,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Network security: Restrict NTLM: Audit Incoming NTLM Traffic",
                    FriendlyDescription =
                        "Options include Disable, Enable auditing for domain accounts, and Enable auditing for all accounts.",
                    Key = "System\\CurrentControlSet\\Control\\Lsa\\MSV1_0",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "AuditReceivingNTLMTraffic",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 0,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Network security: Restrict NTLM: Add remote server exceptions for NTLM authentication",
                    FriendlyDescription =
                        "If configured this policy setting allows you to define a list of remote servers to which clients are allowed to use NTLM authentication.",
                    Key = "System\\CurrentControlSet\\Control\\Lsa\\MSV1_0",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "ClientAllowedNTLMServers",
                    ValueType = RegKeyValType.REG_MULTI_SZ,
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Network security: Restrict NTLM: Incoming NTLM traffic",
                    FriendlyDescription =
                        "Allows you to deny or allow incoming NTLM traffic. Options include Allow all, Deny all domain accounts, and Deny all accounts.",
                    Key = "System\\CurrentControlSet\\Control\\Lsa\\MSV1_0",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "RestrictReceivingNTLMTraffic",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 0,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers",
                    FriendlyDescription =
                        "Allows you to deny or audit outgoing NTLM traffic to any Windows remote server. Options include Allow all, Audit all, and Deny all.",
                    Key = "System\\CurrentControlSet\\Control\\Lsa\\MSV1_0",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "RestrictSendingNTLMTraffic",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 0,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Network security: Do not store LAN Manager hash value on next password change",
                    FriendlyDescription =
                        "Determines if at the next password change, the LAN Manager (LM) hash value for the new password is stored.",
                    Key = "System\\CurrentControlSet\\Control\\Lsa",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "NoLMHash",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 1,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Network access: Do not allow anonymous enumeration of SAM accounts and shares",
                    FriendlyDescription =
                        "Determines whether anonymous enumeration of SAM accounts and shares is allowed.",
                    Key = "System\\CurrentControlSet\\Control\\Lsa",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "RestrictAnonymous",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 0,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Network access: Do not allow anonymous enumeration of SAM accounts",
                    FriendlyDescription =
                        "Allows additional restrictions to be placed on anonymous connections and the enumeration of SAM accounts.",
                    Key = "System\\CurrentControlSet\\Control\\Lsa",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "RestrictAnonymousSAM",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 1,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Network access: Restrict clients allowed to make remote calls to SAM",
                    FriendlyDescription =
                        "Controls which users can enumerate users and groups in the local Security Accounts Manager (SAM) database and Active Directory.",
                    Key = "System\\CurrentControlSet\\Control\\Lsa",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "RestrictRemoteSAM",
                    ValueType = RegKeyValType.REG_SZ,
                    DefaultSz = "",
                    InterestingIf = InterestingIf.NotDefault
                },

                new RegKey()
                {
                    //
                    MsDesc =
                        "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings",
                    FriendlyDescription =
                        "Prevents the application of category-level audit policy from Group Policy and from the Local Security Policy administrative tool",
                    Key = "System\\CurrentControlSet\\Control\\Lsa",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "SCENoApplyLegacyAuditPolicy",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 0,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Domain controller: Allow server operators to schedule tasks",
                    FriendlyDescription =
                        "Determines if Server Operators are allowed to submit jobs by means of the AT schedule facility.",
                    Key = "System\\CurrentControlSet\\Control\\Lsa",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "SubmitControl",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 0,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Network security: Allow Local System to use computer identity for NTLM",
                    FriendlyDescription =
                        "Allows Local System services that use Negotiate to use the computer identity when reverting to NTLM authentication.",
                    Key = "System\\CurrentControlSet\\Control\\Lsa",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "UseMachineId",
                    ValueType = RegKeyValType.REG_DWORD,
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Network access: Remotely accessible registry paths",
                    FriendlyDescription =
                        "This policy setting determines which registry paths and subpaths are accessible when an application or process references the WinReg key to determine access permissions.",
                    Key = "System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedExactPaths",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "Machine",
                    ValueType = RegKeyValType.REG_MULTI_SZ,
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Network access: Remotely accessible registry paths and sub-paths",
                    FriendlyDescription =
                        "Determines which registry paths and subpaths can be accessed over the network, regardless of the users or groups listed in the access control list (ACL) of the winreg registry key.",
                    Key = "System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "Machine",
                    ValueType = RegKeyValType.REG_MULTI_SZ,
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc =
                        "System objects: Strengthen default permissions of internal system objects (e.g., Symbolic Links)",
                    FriendlyDescription =
                        "Determines the strength of the default discretionary access control list (DACL) for objects. is enabled allows users who are not administrators to read shared objects but not allowing these users to modify shared objects that they did not create.",
                    Key = "System\\CurrentControlSet\\Control\\Session Manager",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "ProtectionMode",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 1,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Microsoft network server: Disconnect clients when logon hours expire",
                    FriendlyDescription =
                        "Determines whether to disconnect users who are connected to the local computer outside their user account's valid logon hours. This setting affects the Server Message Block (SMB) component.",
                    Key = "System\\CurrentControlSet\\Services\\LanManServer\\Parameters",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "EnableForcedLogOff",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 1,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Microsoft network server: Attempt S4U2Self to obtain claim information",
                    FriendlyDescription =
                        "This setting determines whether the local file server will attempt to use Kerberos Service-for-User-to-Self (S4U2Self) functionality to obtain a network client principal’s claims from the client’s account domain.",
                    Key = "System\\CurrentControlSet\\Services\\LanManServer\\Parameters",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "EnableS4U2SelfForClaims",
                    ValueType = RegKeyValType.REG_DWORD,
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Microsoft network client: Digitally sign communications (if server agrees)",
                    FriendlyDescription = "Determines whether the SMB client attempts to negotiate SMB packet signing.",
                    Key = "System\\CurrentControlSet\\Services\\LanManServer\\Parameters",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "EnableSecuritySignature",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 0,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Network access: Named Pipes that can be accessed anonymously",
                    FriendlyDescription =
                        "Determines which communication sessions (pipes) will have attributes and permissions that allow anonymous access.",
                    Key = "System\\CurrentControlSet\\Services\\LanManServer\\Parameters",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "NullSessionPipes",
                    ValueType = RegKeyValType.REG_MULTI_SZ,
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Network access: Restrict anonymous access to Named Pipes and Shares",
                    FriendlyDescription = "This security setting restricts anonymous access to shares and pipes",
                    Key = "System\\CurrentControlSet\\Services\\LanManServer\\Parameters",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "NullSessionShares",
                    ValueType = RegKeyValType.REG_MULTI_SZ,
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Microsoft network client: Digitally sign communications (always)",
                    FriendlyDescription = "Determines whether packet signing is required by the SMB client component.",
                    Key = "System\\CurrentControlSet\\Services\\LanManServer\\Parameters",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "RequireSecuritySignature",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 0,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Network access: Restrict anonymous access to Named Pipes and Shares",
                    FriendlyDescription = "This security setting restricts anonymous access to shares and pipes",
                    Key = "System\\CurrentControlSet\\Services\\LanManServer\\Parameters",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "RestrictNullSessAccess",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 1,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Microsoft network server: Server SPN target name validation level",
                    FriendlyDescription =
                        "Determines the level of validation a SMB server performs on the service principal name (SPN) provided by the SMB client when trying to establish a session to an SMB server.",
                    Key = "System\\CurrentControlSet\\Services\\LanManServer\\Parameters",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "SmbServerNameHardeningLevel",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 0,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Microsoft network client: Send unencrypted password to third-party SMB servers",
                    FriendlyDescription =
                        "If enabled, the Server Message Block (SMB) redirector is allowed to send plaintext passwords to non-Microsoft SMB servers that do not support password encryption during authentication.",
                    Key = "System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "EnablePlainTextPassword",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 0,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Yellow
                },

                new RegKey()
                {
                    //
                    MsDesc = "Microsoft network client: Digitally sign communications (if server agrees)",
                    FriendlyDescription =
                        "Determines whether the SMB client attempts to negotiate SMB packet signing. If enabled, the Microsoft network client will ask the server to perform SMB packet signing upon session setup.",
                    Key = "System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "EnableSecuritySignature",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 1,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Microsoft network client: Digitally sign communications (always)",
                    FriendlyDescription =
                        "Determines whether packet signing is required by the SMB client component. If enabled, the Microsoft network client will not communicate with a Microsoft network server unless that server agrees to perform SMB packet signing.",
                    Key = "System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "RequireSecuritySignature",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 0,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    MsDesc = "Network security: LDAP client signing requirements",
                    FriendlyDescription =
                        "determines the level of data signing that is requested on behalf of clients issuing LDAP BIND requests. Options include None, Negotiate signing, and Require Signature.",
                    Key = "System\\CurrentControlSet\\Services\\LDAP",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "LDAPClientIntegrity",
                    ValueType = RegKeyValType.REG_DWORD,
                    GoodDword = 2,
                    InterestingIf = InterestingIf.NotGood,
                    Triage = Constants.Triage.Yellow
                },

                new RegKey()
                {
                    //
                    MsDesc = "Network security: Restrict NTLM: Audit NTLM authentication in this domain",
                    FriendlyDescription =
                        "Allows you to audit NTLM authentication in a domain from this domain controller. If disabled the domain controller will not log events for NTLM authentication in the domain.",
                    Key = "System\\CurrentControlSet\\Services\\Netlogon\\Parameters",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "AuditNTLMInDomain",
                    ValueType = RegKeyValType.REG_DWORD,
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Network security: Restrict NTLM: Add server exceptions in this domain",
                    FriendlyDescription =
                        "Allows the creation of an exception list of servers to which clients are allowed to use NTLM pass-through authentication",
                    Key = "System\\CurrentControlSet\\Services\\Netlogon\\Parameters",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "DCAllowedNTLMServers",
                    ValueType = RegKeyValType.REG_MULTI_SZ,
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Domain member: Disable machine account password changes",
                    FriendlyDescription =
                        "Determines whether a domain member periodically changes its computer account password.",
                    Key = "System\\CurrentControlSet\\Services\\Netlogon\\Parameters",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "DisablePasswordChange",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 0,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Domain member: Maximum machine account password age",
                    FriendlyDescription =
                        "Determines how often a domain member will attempt to change its computer account password.",
                    Key = "System\\CurrentControlSet\\Services\\Netlogon\\Parameters",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "MaximumPasswordAge",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 30,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Domain controller: Refuse machine account password changes",
                    FriendlyDescription =
                        "Determines whether domain controllers will refuse requests from member computers to change computer account passwords.",
                    Key = "System\\CurrentControlSet\\Services\\Netlogon\\Parameters",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "RefusePasswordChange",
                    ValueType = RegKeyValType.REG_DWORD,
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Domain member: Digitally encrypt or sign secure channel data (always)",
                    FriendlyDescription =
                        "Determines whether all secure channel traffic initiated by the domain member must be signed or encrypted.",
                    Key = "System\\CurrentControlSet\\Services\\Netlogon\\Parameters",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "RequireSignOrSeal",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 1,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Domain member: Require strong (Windows 2000 or later) session key",
                    FriendlyDescription =
                        "Determines whether 128-bit key strength is required for encrypted secure channel data.",
                    Key = "System\\CurrentControlSet\\Services\\Netlogon\\Parameters",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "RequireStrongKey",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 1,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Network security: Restrict NTLM: NTLM authentication in this domain",
                    FriendlyDescription =
                        "Allows you to deny or allow NTLM authentication within a domain from a domain controller.",
                    Key = "System\\CurrentControlSet\\Services\\Netlogon\\Parameters",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "RestrictNTLMInDomain",
                    ValueType = RegKeyValType.REG_DWORD,
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Domain member: Digitally encrypt secure channel data (when possible)",
                    FriendlyDescription =
                        "Determines whether a domain member attempts to negotiate encryption for all secure channel traffic that it initiates.",
                    Key = "System\\CurrentControlSet\\Services\\Netlogon\\Parameters",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "SealSecureChannel",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 1,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Domain member: Digitally sign secure channel data (when possible)",
                    FriendlyDescription =
                        "Determines whether a domain member attempts to negotiate signing for all secure channel traffic that it initiates.",
                    Key = "System\\CurrentControlSet\\Services\\Netlogon\\Parameters",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "SignSecureChannel",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 1,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                new RegKey()
                {
                    //
                    MsDesc = "Domain controller: LDAP server signing requirements",
                    FriendlyDescription =
                        "Determines whether the LDAP server requires signing to be negotiated with LDAP clients,",
                    Key = "System\\CurrentControlSet\\Services\\NTDS\\Parameters",
                    RegHive = RegHive.HKEY_LOCAL_MACHINE,
                    ValueName = "LDAPServerIntegrity ",
                    ValueType = RegKeyValType.REG_DWORD,
                    DefaultDword = 0,
                    InterestingIf = InterestingIf.NotDefault,
                    Triage = Constants.Triage.Green
                },

                // OK THIS IS WHERE 3rd PARTY SHIT STARTS

                new RegKey()
                {
                    MsDesc = "ePolicy Orchestrator Password Storage",
                    FriendlyDescription = "ePolicy Orchestrator Password Storage",
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Red,
                    Key = "Network Associates\\ePolicy Orchestrator",
                },
                new RegKey()
                {//
                    MsDesc = "FileZilla Server Password Storage",
                    FriendlyDescription = "FileZilla Server Password Storage",
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Red,
                    Key = "Software\\FileZilla\\Site Manager\\",
                },
                new RegKey()
                {//
                    MsDesc = "McAfee Desktop Protection UI Password",
                    FriendlyDescription = "McAfee Desktop Protection UI Password",
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Red,
                    Key = "Wow6432Node\\McAfee\\DesktopProtection - McAfee VSE",
                },
                new RegKey()
                {//
                    MsDesc = "McAfee Desktop Protection UI Password",
                    FriendlyDescription = "McAfee Desktop Protection UI Password",
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Red,
                    Key = "McAfee\\DesktopProtection - McAfee VSE",
                },
                new RegKey()
                {//
                    MsDesc = "VNC Server credential storage.",
                    FriendlyDescription = "VNC Server credential storage.",
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Red,
                    Key = "ORL\\WinVNC3",
                },
                new RegKey()
                {//
                    MsDesc = "VNC Server credential storage.",
                    FriendlyDescription = "VNC Server credential storage.",
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Red,
                    Key = "RealVNC\\WinVNC4",
                },
                new RegKey()
                {//
                    MsDesc = "VNC Server credential storage.",
                    FriendlyDescription = "VNC Server credential storage.",
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Red,
                    Key = "RealVNC\\Default",
                },
                new RegKey()
                {//
                    MsDesc = "VNC Server credential storage.",
                    FriendlyDescription = "VNC Server credential storage.",
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Red,
                    Key = "TightVNC\\Server",
                },
                new RegKey()
                {//
                MsDesc = "Sage MicrOpay Meridian database credential storage.",
                FriendlyDescription = "Sage MicrOpay Meridian database credential storage.",
                RegHive = RegHive.HKEY_CURRENT_USER,
                InterestingIf = InterestingIf.Present,
                Triage = Constants.Triage.Red,
                Key = "Software\\SageMicrOpay\\Meridian\\Common"
                },
                new RegKey()
                {//
                MsDesc = "Sage MicrOpay Meridian database credential storage.",
                FriendlyDescription = "Sage MicrOpay Meridian database credential storage.",
                RegHive = RegHive.HKEY_CURRENT_USER,
                InterestingIf = InterestingIf.Present,
                Triage = Constants.Triage.Red,
                Key = "Software\\SageMicrOpay\\Meridian\\BDM",
                },
                new RegKey()
                {
                    MsDesc = "SNMP Creds",
                    FriendlyDescription = "",
                    Key = "CurrentControlSet\\Services\\SNMP",
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Yellow
                },
                new RegKey()
                {
                    MsDesc = "PuTTY Stored Creds",
                    FriendlyDescription = "",
                    Key = "SimonTatham\\PuTTY\\Sessions",
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Yellow
                },
                new RegKey()
                {
                    MsDesc = "SCCM OSD Stored Creds",
                    FriendlyDescription = "",
                    Key = "Microsoft\\MPSD\\OSD",
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Yellow
                },

                 new RegKey()
                {
                    MsDesc = "TeamViewer Stored Creds",
                    FriendlyDescription = "",
                    Key = "WOW6432Node\\TeamViewer",
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Yellow
                },

                 new RegKey()
                {
                    MsDesc = "WinSCP Stored Creds",
                    FriendlyDescription = "",
                    Key = "Software\\Martin Prikryl\\WinSCP 2\\Sessions",
                    InterestingIf = InterestingIf.Present,
                    Triage = Constants.Triage.Yellow
                },
            };
        }
    }
}