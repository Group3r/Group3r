using System.Collections.Generic;

namespace Group3r.Options.AssessmentOptions
{
    public partial class AssessmentOptions
    {
        public void LoadPrivRights()
        {
            //TODO : Reference https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment
            // to make these nicer for users

            PrivRights = new List<PrivRightOption>()
            {
                new PrivRightOption()
                {
                    PrivRightName = "SeTakeOwnershipPrivilege",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = true,
                    LocalPrivescDesc = "Can be used to grant yourself ownership on any file, registry key, etc.",
                    MsDescription = "Take ownership of files or other objects"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeSyncAgentPrivilege",
                    GrantsRemoteAccess = true,
                    RemoteAccessDesc = "",
                    LocalPrivesc = true,
                    LocalPrivescDesc = "",
                    MsDescription = "Synchronize directory service data"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeShutdownPrivilege",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = false,
                    LocalPrivescDesc = "",
                    MsDescription = "Shut down the system"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeRelabelPrivilege",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = true,
                    LocalPrivescDesc = "",
                    MsDescription = ""
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeRestorePrivilege",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = true,
                    LocalPrivescDesc = "Can be used to overwrite/modify any file.",
                    MsDescription = "Restore files and directories"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeTrustedCredManAccessPrivilege",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = true,
                    LocalPrivescDesc = "Microsoft provides the following additional detail: If an account is given this user right, the user of the account may create an application that calls into Credential Manager and is returned the credentials for another user.",
                    MsDescription = "Access Credential Manager as a trusted caller"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeNetworkLogonRight",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = false,
                    LocalPrivescDesc = "",
                    MsDescription = "Access this computer from the network"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeTcbPrivilege",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = true,
                    LocalPrivescDesc = "Lets you impersonate any other user.",
                    MsDescription = "Act as part of the operating system"
                },

                new PrivRightOption()
                {
                    PrivRightName = "SeAssignPrimaryTokenPrivilege",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = true,
                    LocalPrivescDesc = "Lets you impersonate accounts (after some backflips) look at the various 'potato' attacks, i.e. Rotten, Juicy, etc.",
                    MsDescription = "Replace a process level token"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeUndockPrivilege",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = false,
                    LocalPrivescDesc = "",
                    MsDescription = "Remove computer from docking station"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeSystemProfilePrivilege",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = false,
                    LocalPrivescDesc = "",
                    MsDescription = "Profile system performance"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeProfileSingleProcessPrivilege",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = false,
                    LocalPrivescDesc = "",
                    MsDescription = "Profile single process"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeMachineAccountPrivilege",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = false,
                    LocalPrivescDesc = "",
                    MsDescription = "Add workstations to domain - l0ss note: This can be leveraged as one part of that Resource Based Constrained Delegation kerberos backflip attack."
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeRemoteInteractiveLogonRight",
                    GrantsRemoteAccess = true,
                    RemoteAccessDesc = "It's RDP. Good old RDP.",
                    LocalPrivesc = false,
                    LocalPrivescDesc = "",
                    MsDescription = "Allow log on through Remote Desktop Services"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeIncreaseQuotaPrivilege",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = false,
                    LocalPrivescDesc = "",
                    MsDescription = "Adjust memory quotas for a process"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeInteractiveLogonRight",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = false,
                    LocalPrivescDesc = "",
                    MsDescription = "Allow log on locally"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeBackupPrivilege",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = true,
                    LocalPrivescDesc = "Lets you override file and directory permissions to read any file on the FS.",
                    MsDescription = "Back up files and directories"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeChangeNotifyPrivilege",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = false,
                    LocalPrivescDesc = "",
                    MsDescription = "Bypass traverse checking"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeSystemtimePrivilege",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = false,
                    LocalPrivescDesc = "",
                    MsDescription = "Change the system time"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeCreatePagefilePrivilege",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = false,
                    LocalPrivescDesc = "",
                    MsDescription = "Create a pagefile"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeCreateTokenPrivilege",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = true,
                    LocalPrivescDesc = "Lets you grant yourself any access you want. Locally.",
                    MsDescription = "Create a token object"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeCreateGlobalPrivilege",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = false,
                    LocalPrivescDesc = "",
                    MsDescription = "Create global objects"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeCreatePermanentPrivilege",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = false,
                    LocalPrivescDesc = "",
                    MsDescription = "Create permanent shared objects"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeCreateSymbolicLinkPrivilege",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = true,
                    LocalPrivescDesc = "",
                    MsDescription = "Create symbolic links"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeDebugPrivilege",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = true,
                    LocalPrivescDesc = "Lets you do the mimikatz thing, you know, dump lsass.exe, cool stuff like that.",
                    MsDescription = "Debug programs"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeDenyNetworkLogonRight",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = false,
                    LocalPrivescDesc = "",
                    MsDescription = "Deny access to this computer from the network"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeDenyBatchLogonRight",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = false,
                    LocalPrivescDesc = "",
                    MsDescription = "Deny log on as a batch job"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeDenyServiceLogonRight",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = false,
                    LocalPrivescDesc = "",
                    MsDescription = "Deny log on as a service"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeDenyInteractiveLogonRight",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = false,
                    LocalPrivescDesc = "",
                    MsDescription = "Deny log on locally"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeDenyRemoteInteractiveLogonRight",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = false,
                    LocalPrivescDesc = "",
                    MsDescription = "Deny log on through Remote Desktop Services"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeRemoteShutdownPrivilege",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = false,
                    LocalPrivescDesc = "",
                    MsDescription = "Force shutdown from a remote system"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeAuditPrivilege",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = false,
                    LocalPrivescDesc = "",
                    MsDescription = "Generate security audits"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeImpersonatePrivilege",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = true,
                    LocalPrivescDesc = "Lets you impersonate accounts (after some backflips) look at the various 'potato' attacks, i.e. Rotten, Juicy, etc.",
                    MsDescription = "Impersonate a client after authentication"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeIncreaseWorkingSetPrivilege",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = false,
                    LocalPrivescDesc = "",
                    MsDescription = "Increase a process working set"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeIncreaseBasePriorityPrivilege",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = false,
                    LocalPrivescDesc = "",
                    MsDescription = "Increase scheduling priority"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeLoadDriverPrivilege",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = true,
                    LocalPrivescDesc = "Lets you load device drivers. Privesc in this case is usually going to mean loading a known-vulnerable driver and then exploiting the known vulnerability.",
                    MsDescription = "Load and unload device drivers"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeLockMemoryPrivilege",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = false,
                    LocalPrivescDesc = "",
                    MsDescription = "Lock pages in memory"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeBatchLogonRight",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = false,
                    LocalPrivescDesc = "",
                    MsDescription = "Log on as a batch job"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeServiceLogonRight",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = false,
                    LocalPrivescDesc = "",
                    MsDescription = "Log on as a service"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeSecurityPrivilege",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = false,
                    LocalPrivescDesc = "",
                    MsDescription = "Manage auditing and security log"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeSystemEnvironmentPrivilege",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = false,
                    LocalPrivescDesc = "",
                    MsDescription = "Modify firmware environment values"
                },
                new PrivRightOption()
                {
                    PrivRightName = "SeManageVolumePrivilege",
                    GrantsRemoteAccess = false,
                    RemoteAccessDesc = "",
                    LocalPrivesc = false,
                    LocalPrivescDesc = "",
                    MsDescription = "Perform volume maintenance tasks"
                }
            };
        }
    }
}