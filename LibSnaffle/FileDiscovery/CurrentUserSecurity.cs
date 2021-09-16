using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace LibSnaffle.FileDiscovery
{

    public class CurrentUserSecurity
    {
        private readonly WindowsPrincipal _currentPrincipal;
        private readonly WindowsIdentity _currentUser;

        public CurrentUserSecurity()
        {
            _currentUser = WindowsIdentity.GetCurrent();
            _currentPrincipal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
        }

        public bool HasAccess(DirectoryInfo directory, FileSystemRights right)
        {
            try
            {
                // Get the collection of authorization rules that apply to the directory.
                AuthorizationRuleCollection acl = directory.GetAccessControl()
                    .GetAccessRules(true, true, typeof(SecurityIdentifier));
                return HasFileOrDirectoryAccess(right, acl);
            }

            catch (UnauthorizedAccessException)
            {
                return false;
            }
        }

        public bool HasAccess(FileInfo file, FileSystemRights right)
        {
            try
            {
                // Get the collection of authorization rules that apply to the file.
                AuthorizationRuleCollection acl = file.GetAccessControl()
                    .GetAccessRules(true, true, typeof(SecurityIdentifier));

                return HasFileOrDirectoryAccess(right, acl);
            }

            catch (UnauthorizedAccessException)
            {
                return false;
            }
        }

        public bool HasFileOrDirectoryAccess(FileSystemRights right,
            AuthorizationRuleCollection acl)
        {
            bool allow = false;
            bool inheritedAllow = false;
            bool inheritedDeny = false;

            for (int i = 0; i < acl.Count; i++)
            {
                FileSystemAccessRule currentRule = (FileSystemAccessRule)acl[i];
                // If the current rule applies to the current user.
                if (_currentUser.User.Equals(currentRule.IdentityReference) ||
                    _currentPrincipal.IsInRole(
                        (SecurityIdentifier)currentRule.IdentityReference))
                {
                    if (currentRule.AccessControlType.Equals(AccessControlType.Deny))
                    {
                        if ((currentRule.FileSystemRights & right) == right)
                        {
                            if (currentRule.IsInherited)
                                inheritedDeny = true;
                            else
                                // Non inherited "deny" takes overall precedence.
                                return false;
                        }
                    }
                    else if (currentRule.AccessControlType
                        .Equals(AccessControlType.Allow))
                    {
                        if ((currentRule.FileSystemRights & right) == right)
                        {
                            if (currentRule.IsInherited)
                                inheritedAllow = true;
                            else
                                allow = true;
                        }
                    }
                }
            }

            if (allow)
                // Non inherited "allow" takes precedence over inherited rules.
                return true;

            return inheritedAllow && !inheritedDeny;
        }
    }
}
