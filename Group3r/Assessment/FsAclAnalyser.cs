using LibSnaffle.Classifiers.Results;
using Sddl.Parser;
using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using Group3r.Options.AssessmentOptions;
using System.Collections.Generic;
using System.Linq;

namespace Group3r.Assessment
{
    public class FsAclResult
    {
        public RwStatus RwStatus { get; set; }
        public List<SimpleAce> InterestingAces { get; set; } = new List<SimpleAce>();
        public List<GpoFinding> Findings { get; set; } = new List<GpoFinding>();
    }

    public class FsAclAnalyser
    {
        public AssessmentOptions AssessmentOptions {get; set; }
        public SddlAnalyser SddlAnalyser { get; set; }

        //public string[] ReadRights { get; set; } = new string[] { "Read", "ReadAndExecute", "ReadData", "ListDirectory" };
        public string[] WriteRights { get; set; } = new string[] { "CREATE_LINK", "WRITE", "WRITE_OWNER", "WRITE_DAC", "APPEND_DATA", "WRITE_DATA", "CREATE_CHILD", "FILE_WRITE", "ADD_FILE", "ADD_SUBDIRECTORY" };
        public string[] ModifyRights { get; set; } = new string[] { "STANDARD_RIGHTS_ALL", "STANDARD_DELETE", "DELETE_TREE", "FILE_ALL", "GENERIC_ALL", "GENERIC_WRITE", "WRITE_OWNER", "WRITE_DAC", "Owner", "DELETE_CHILD" };
        public FsAclAnalyser(AssessmentOptions assessmentOptions)
        {
            AssessmentOptions = assessmentOptions;
            SddlAnalyser = new SddlAnalyser(assessmentOptions);
        }

        public FsAclResult AnalyseFsAcl(FileSystemInfo filesysInfo)
        {
            bool suckItAndSee = false;
            RwStatus rwStatus = new RwStatus() { Exists = false, CanRead = false, CanModify = false, CanWrite = false };

            if (AssessmentOptions.SuckItAndSee)
            {
                try
                {
                    if (filesysInfo.GetType() == typeof(FileInfo))
                    {
                        var writer = new FileStream(filesysInfo.FullName, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
                        writer.Close();
                    }
                    if (filesysInfo.GetType() == typeof(DirectoryInfo))
                    {
                        var tempfile = filesysInfo.FullName + "\\" + Guid.NewGuid().ToString() + ".gp3";
                        var tfStream = File.Create(tempfile);
                        tfStream.Close();
                        try
                        {
                            File.Delete(tempfile);
                        }
                        catch
                        {
                            Console.WriteLine("Failed to delete " + tempfile + " which is a bit messy but you knew what you were in for.");
                            //who cares, we are being messy.
                        }
                    }
                    rwStatus.CanModify = true;
                    rwStatus.CanWrite = true;
                }
                catch (System.IO.FileNotFoundException e)
                {
                    rwStatus.CanWrite = false;
                    rwStatus.CanModify = false;
                }
                catch (System.IO.DirectoryNotFoundException e)
                {
                    rwStatus.CanWrite = false;
                    rwStatus.CanModify = false;
                }
                catch (Exception e)
                {
                    rwStatus.CanWrite = false;
                    rwStatus.CanModify = false;
                    Console.WriteLine(e.ToString());
                }
                try
                {
                    if (filesysInfo.GetType() == typeof(FileInfo))
                    {
                        var reader = new FileStream(filesysInfo.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        reader.Close();
                    }
                    if (filesysInfo.GetType() == typeof(DirectoryInfo))
                    {
                        var files = ((DirectoryInfo)filesysInfo).EnumerateFiles();
                    }
                    rwStatus.CanRead = true;
                }
                catch (System.IO.DirectoryNotFoundException e)
                {
                    rwStatus.CanRead = false;
                }
                catch (System.IO.FileNotFoundException e)
                {
                    rwStatus.CanRead = false;
                }
                catch (Exception e)
                {
                    rwStatus.CanRead = false;
                    Console.WriteLine(e.ToString());
                }
            }
            else
            {
                if (AssessmentOptions.TrusteeOptions == null)
                {
                    throw new ArgumentException("If you aren't running in 'suck it and see' mode, the TargetTrustees option needs to be populated somehow.");
                }
                try
                {
                    Sddl.Parser.Sddl parsedSddl = null;
                    string sddl;
                    // first we check if the thing even exists and we can look at it.
                    if (filesysInfo.GetType() == typeof(DirectoryInfo))
                    {
                        if (Directory.Exists(filesysInfo.FullName))
                        {
                            // then we get the access control as an sddl because that's our lowest-common-denominator format for parsing/assessing these things.
                            rwStatus.Exists = true;
                            DirectorySecurity dirSecurity = Directory.GetAccessControl(filesysInfo.FullName, AccessControlSections.Owner | AccessControlSections.Access);
                            sddl = dirSecurity.GetSecurityDescriptorSddlForm(AccessControlSections.Owner | AccessControlSections.Access);
                            parsedSddl = new Sddl.Parser.Sddl(sddl, SecurableObjectType.Directory);
                        }
                    }
                    else if (filesysInfo.GetType() == typeof(FileInfo))
                    {
                        if (File.Exists(filesysInfo.FullName))
                        {
                            rwStatus.Exists = true;
                            FileSecurity fileSecurity = File.GetAccessControl(filesysInfo.FullName, AccessControlSections.Owner | AccessControlSections.Access);
                            sddl = fileSecurity.GetSecurityDescriptorSddlForm(AccessControlSections.Owner | AccessControlSections.Access);
                            parsedSddl = new Sddl.Parser.Sddl(sddl, SecurableObjectType.File);
                        }
                    }

                    // if it doesn't exist then might as well bail out now.
                    if (!rwStatus.Exists)
                    {
                        return new FsAclResult() { RwStatus = rwStatus };
                    }

                    FsAclResult fsAclResult = new FsAclResult();

                    if (parsedSddl != null)
                    {
                        // Parse the SDDL into a workable format
                        List<SimpleAce> analysedSddl = SddlAnalyser.AnalyseSddl(parsedSddl);

                        foreach (SimpleAce simpleAce in analysedSddl)
                        {
                            bool grantsWrite = false;
                            bool grantsModify = false;
                            bool denyRight = false;
                            //see if any of the rights are interesting
                            foreach (string right in simpleAce.Rights)
                            {
                                //if (ReadRights.Contains(right)) { rwStatus.CanRead = true; }
                                if (WriteRights.Contains(right)) { grantsWrite = true; }
                                if (ModifyRights.Contains(right)) { grantsModify = true; }
                            }

                            // check if it's allow or deny
                            if (simpleAce.ACEType == ACEType.Deny) { denyRight = true; }

                            if (denyRight) { continue; } // TODO actually ahandle deny rights properly

                            //see if the trustee is a users/group we know about.
                            IEnumerable<TrusteeOption> nameMatches = AssessmentOptions.TrusteeOptions.Where(trusteeopt => trusteeopt.DisplayName == simpleAce.Trustee.DisplayName);
                            IEnumerable<TrusteeOption> sidMatches = AssessmentOptions.TrusteeOptions.Where(trusteeopt => trusteeopt.SID == simpleAce.Trustee.Sid);

                            TrusteeOption match = new TrusteeOption();
                            if (nameMatches.Any()) { match = nameMatches.First(); }
                            if (sidMatches.Any()) { match = sidMatches.First(); }
                            if (match.DisplayName != null)
                            {
                                // so if it's a user/group that we know about...
                                if (match.Target || match.LowPriv)
                                {
                                    // and it's either canonically low-priv or we are a member of it
                                    //set rwStatus based on it.
                                    if (grantsModify) { rwStatus.CanModify = true; }
                                    if (grantsWrite) { rwStatus.CanRead = true; }
                                    if (grantsModify || grantsWrite)
                                    {
                                        fsAclResult.InterestingAces.Add(simpleAce);
                                    }
                                }
                                else if (!match.HighPriv)
                                {
                                    fsAclResult.InterestingAces.Add(simpleAce);
                                    if (grantsModify || grantsWrite)
                                    {
                                        fsAclResult.InterestingAces.Add(simpleAce);
                                    }
                                }
                            }
                            else
                            {
                                // otherwise there's no match.
                                if (grantsModify || grantsWrite)
                                {
                                    fsAclResult.InterestingAces.Add(simpleAce);
                                }
                            }
                        }
                        fsAclResult.RwStatus = rwStatus;
                        return fsAclResult;
                    }
                    else
                    {
                        throw new Exception("File/Folder ACL not read/parsed properly.");
                    }


                    /*
                    when checking a file:
                create our simple model blanked
                get all the aces
                foreach ace:
                    if the group is in our well-known-sid list as 'canonically low-priv':
                        check if it's an allow or a deny
                        check what access it grants/denies
                        set that into our result, break
                    if it's a domain trustee:
                        check if the trustee appears in our list
                        check if it's an 'allow' or a 'deny'
                        check what acess it grants/denies
                        set that into our result, break
                    if the ace trustee is local to a computer or is from a a diff domain:
                        check if we are doing remote sam enumeration:
                            do that - one day - when you can be fucked.
                    */

                    


                    //Console.WriteLine(parsedSddl.ToString());
                }
                catch (UnauthorizedAccessException e)
                {
                    return new FsAclResult() { RwStatus = rwStatus };
                }

            }
            return new FsAclResult() { RwStatus = rwStatus };
        }
    }

    public enum AllowDeny
    {
        Unset,
        Allow,
        Deny
    }

    public class FileRight
    {
        string RightName { get; set; }
        bool ReadRight { get; set; } = false;
        bool WriteRight { get; set; } = false;
        bool ModifyRight { get; set; } = false;
        AllowDeny AllowDeny { get; set; } = AllowDeny.Unset;
    }
}
/*
    public class EffectivePermissions
    {
        public string[] ReadRights { get; set; } = new string[] { "Read", "ReadAndExecute", "ReadData", "ListDirectory" };
        public string[] WriteRights { get; set; } = new string[] { "Write", "Modify", "FullControl", "TakeOwnership", "ChangePermissions", "AppendData", "WriteData", "CreateFiles", "CreateDirectories" };
        public string[] ModifyRights { get; set; } = new string[] { "Modify", "FullControl", "TakeOwnership", "ChangePermissions" };
        public List<string> TargetTrustees { get; set; }


        public EffectivePermissions(List<string> targetTrustees)
        {
            TargetTrustees = targetTrustees;
        }
        public RwStatus CanRw(FileSystemInfo filesysInfo)
        {
            try
            {
                RwStatus rwStatus = new RwStatus { CanWrite = false, CanRead = false, CanModify = false };

                foreach (string trustee in TargetTrustees)
                {
                    string[] accessStrings = GetEffectivePermissions(filesysInfo, trustee);

                    foreach (string access in accessStrings)
                    {
                        if (access == "FullControl")
                        {
                            rwStatus.CanModify = true;
                            rwStatus.CanRead = true;
                            rwStatus.CanWrite = true;
                        }
                        if (ReadRights.Contains(access))
                        {
                            rwStatus.CanRead = true;
                        }
                        if (WriteRights.Contains(access))
                        {
                            rwStatus.CanWrite = true;
                        }
                        if (ModifyRights.Contains(access))
                        {
                            rwStatus.CanModify = true;
                        }
                    }
                }

                return rwStatus;
            }
            catch (Exception e)
            {
                return new RwStatus { CanWrite = false, CanRead = false, CanModify = false }; ;
            }
        }
        public string[] GetEffectivePermissions(FileSystemInfo filesysInfo, string username)
        {
            EffectiveAccessInfo effectiveAccessInfo;

            string servername = "localhost";

            IdentityReference2 idRef2 = new IdentityReference2(username);
            if (filesysInfo.FullName.StartsWith("\\\\"))
            {
                servername = filesysInfo.FullName.Split('\\')[2];
            }
            try
            {
                if (filesysInfo.GetType() == typeof(DirectoryInfo))
                {
                    Alphaleonis.Win32.Filesystem.DirectoryInfo item = new Alphaleonis.Win32.Filesystem.DirectoryInfo(filesysInfo.FullName);
                    effectiveAccessInfo = EffectiveAccess.GetEffectiveAccess(item, idRef2, servername);
                }
                else
                {
                    Alphaleonis.Win32.Filesystem.FileInfo item = new Alphaleonis.Win32.Filesystem.FileInfo(filesysInfo.FullName);
                    effectiveAccessInfo = EffectiveAccess.GetEffectiveAccess(item, idRef2, servername);
                }

                string accesslist = effectiveAccessInfo.Ace.AccessRights.ToString();

                string[] accesslistarray = accesslist.Replace(" ", "").Split(',');

                return accesslistarray;
            }
            catch (Exception e)
            {
                return new string[1] { "None" };
            }
        }

    }
    public class EffectiveAccess
    {
        public static EffectiveAccessInfo GetEffectiveAccess(
          Alphaleonis.Win32.Filesystem.FileSystemInfo item,
          IdentityReference2 id,
          string serverName)
        {
            bool remoteServerAvailable = false;
            Exception authzException = (Exception)null;
            int effectiveAccess = new Win32().GetEffectiveAccess((ObjectSecurity)new FileSystemSecurity2(item).SecurityDescriptor, id, serverName, out remoteServerAvailable, out authzException);
            return new EffectiveAccessInfo(new FileSystemAccessRule2(new FileSystemAccessRule((IdentityReference)(SecurityIdentifier)id, (FileSystemRights)effectiveAccess, AccessControlType.Allow), item), remoteServerAvailable, authzException);
        }
    }

    public class EffectiveAccessInfo
    {
        private FileSystemAccessRule2 ace;
        private bool fromRemote;
        private Exception authzException;

        public FileSystemAccessRule2 Ace => ace;

        public bool FromRemote => fromRemote;

        public Exception AuthzException => authzException;

        public bool OperationFailed => authzException != null;

        public EffectiveAccessInfo(
          FileSystemAccessRule2 ace,
          bool fromRemote,
          Exception authzException = null)
        {
            this.ace = ace;
            this.fromRemote = fromRemote;
            this.authzException = authzException;
        }
    }

    public class IdentityReference2
    {
        protected static Regex sidValidation = new Regex("(S-1-)[0-9-]+", RegexOptions.IgnoreCase);
        protected SecurityIdentifier sid;
        protected NTAccount ntAccount;
        protected string lastError;

        public string Sid => sid.Value;

        public string AccountName => !(ntAccount != (NTAccount)null) ? string.Empty : ntAccount.Value;

        public string LastError => lastError;

        public IdentityReference2(IdentityReference ir)
        {
            ntAccount = ir as NTAccount;
            if (ntAccount != (NTAccount)null)
            {
                sid = (SecurityIdentifier)ntAccount.Translate(typeof(SecurityIdentifier));
            }
            else
            {
                sid = ir as SecurityIdentifier;
                if (!(sid != (SecurityIdentifier)null))
                    return;
                try
                {
                    ntAccount = (NTAccount)sid.Translate(typeof(NTAccount));
                }
                catch (Exception ex)
                {
                    lastError = ex.Message;
                }
            }
        }

        public IdentityReference2(string value)
        {
            Match match = !string.IsNullOrEmpty(value) ? IdentityReference2.sidValidation.Match(value) : throw new ArgumentException("The value cannot be empty");
            if (!string.IsNullOrEmpty(match.Value))
            {
                try
                {
                    sid = new SecurityIdentifier(match.Value);
                }
                catch (Exception ex)
                {
                    throw new InvalidCastException("Could not create an IdentityReference2 with the given SID", ex);
                }
                try
                {
                    ntAccount = (NTAccount)sid.Translate(typeof(NTAccount));
                }
                catch (Exception ex)
                {
                    lastError = ex.Message;
                }
            }
            else
            {
                try
                {
                    ntAccount = new NTAccount(value);
                    sid = (SecurityIdentifier)ntAccount.Translate(typeof(SecurityIdentifier));
                }
                catch (IdentityNotMappedException ex)
                {
                    throw ex;
                }
            }
        }

        public static explicit operator NTAccount(IdentityReference2 ir2) => ir2.ntAccount;

        public static explicit operator IdentityReference2(NTAccount ntAccount) => new IdentityReference2((IdentityReference)ntAccount);

        public static explicit operator SecurityIdentifier(IdentityReference2 ir2) => ir2.sid;

        public static explicit operator IdentityReference2(SecurityIdentifier sid) => new IdentityReference2((IdentityReference)sid);

        public static implicit operator IdentityReference(IdentityReference2 ir2) => (IdentityReference)ir2.sid;

        public static implicit operator IdentityReference2(IdentityReference ir) => new IdentityReference2(ir);

        public static implicit operator IdentityReference2(string value) => new IdentityReference2(value);

        public static implicit operator string(IdentityReference2 ir2) => ir2.ToString();

        public override bool Equals(object obj)
        {
            if (obj == null)
                return false;
            if ((object)this == obj)
                return true;
            SecurityIdentifier securityIdentifier = obj as SecurityIdentifier;
            if (securityIdentifier != (SecurityIdentifier)null)
                return sid == securityIdentifier;
            NTAccount ntAccount = obj as NTAccount;
            if (ntAccount != (NTAccount)null)
                return this.ntAccount == ntAccount;
            IdentityReference2 identityReference2 = obj as IdentityReference2;
            if (identityReference2 != (IdentityReference2)null)
                return sid == identityReference2.sid;
            return obj is string str && (sid.Value == str || this.ntAccount != (NTAccount)null && this.ntAccount.Value.ToLower() == str.ToLower());
        }

        public override int GetHashCode() => sid.GetHashCode();

        public static bool operator ==(IdentityReference2 ir1, IdentityReference2 ir2)
        {
            if ((object)ir1 == (object)ir2)
                return true;
            return !((object)ir1 == null | (object)ir2 == null) && ir1.Equals((object)ir2);
        }

        public static bool operator !=(IdentityReference2 ir1, IdentityReference2 ir2)
        {
            if ((object)ir1 == (object)ir2)
                return false;
            return (object)ir1 == null | (object)ir2 == null || !ir1.Equals((object)ir2);
        }

        public byte[] GetBinaryForm()
        {
            byte[] binaryForm = new byte[sid.BinaryLength];
            sid.GetBinaryForm(binaryForm, 0);
            return binaryForm;
        }

        public override string ToString() => ntAccount == (NTAccount)null ? sid.ToString() : ntAccount.ToString();
    }

    internal class Win32
    {
        private const string ADVAPI32_DLL = "advapi32.dll";
        internal const string KERNEL32_DLL = "kernel32.dll";
        internal const string AUTHZ_DLL = "authz.dll";
        internal const string AUTHZ_OBJECTUUID_WITHCAP = "9a81c2bd-a525-471d-a4ed-49907c0b23da";
        internal const string RCP_OVER_TCP_PROTOCOL = "ncacn_ip_tcp";
        private IntPtr userClientCtxt = IntPtr.Zero;
        private SafeAuthzRMHandle authzRM;
        private IntPtr pGrantedAccess = IntPtr.Zero;
        private IntPtr pErrorSecObj = IntPtr.Zero;

        [DllImport("advapi32.dll", EntryPoint = "GetInheritanceSourceW", CharSet = CharSet.Unicode)]
        private static extern uint GetInheritanceSource(
          [MarshalAs(UnmanagedType.LPTStr)] string pObjectName,
          ResourceType ObjectType,
          SECURITY_INFORMATION SecurityInfo,
          [MarshalAs(UnmanagedType.Bool)] bool Container,
          IntPtr pObjectClassGuids,
          uint GuidCount,
          byte[] pAcl,
          IntPtr pfnArray,
          ref Win32.GENERIC_MAPPING pGenericMapping,
          IntPtr pInheritArray);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        private static extern uint FreeInheritedFromArray(
          IntPtr pInheritArray,
          ushort AceCnt,
          IntPtr pfnArray);

        [DllImport("authz.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AuthzInitializeRemoteResourceManager(
          IntPtr rpcInitInfo,
          out SafeAuthzRMHandle authRM);

        [DllImport("authz.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AuthzInitializeResourceManager(
          AuthzResourceManagerFlags flags,
          IntPtr pfnAccessCheck,
          IntPtr pfnComputeDynamicGroups,
          IntPtr pfnFreeDynamicGroups,
          string szResourceManagerName,
          out SafeAuthzRMHandle phAuthzResourceManager);

        [DllImport("authz.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AuthzInitializeContextFromSid(
          AuthzInitFlags flags,
          byte[] rawUserSid,
          SafeAuthzRMHandle authzRM,
          IntPtr expirationTime,
          Win32.LUID Identifier,
          IntPtr DynamicGroupArgs,
          out IntPtr authzClientContext);

        [DllImport("authz.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AuthzAccessCheck(
          Win32.AuthzACFlags flags,
          IntPtr hAuthzClientContext,
          ref Win32.AUTHZ_ACCESS_REQUEST pRequest,
          IntPtr AuditEvent,
          byte[] rawSecurityDescriptor,
          IntPtr[] OptionalSecurityDescriptorArray,
          uint OptionalSecurityDescriptorCount,
          ref Win32.AUTHZ_ACCESS_REPLY pReply,
          IntPtr cachedResults);

        [DllImport("authz.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AuthzFreeContext(IntPtr authzClientContext);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        public static extern uint GetSecurityDescriptorLength(IntPtr pSecurityDescriptor);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint GetSecurityInfo(
          SafeFileHandle handle,
          ObjectType objectType,
          SecurityInformationClass infoClass,
          IntPtr owner,
          IntPtr group,
          IntPtr dacl,
          IntPtr sacl,
          out IntPtr securityDescriptor);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern SafeFileHandle CreateFile(
          string lpFileName,
          FileAccess desiredAccess,
          FileShare shareMode,
          IntPtr lpSecurityAttributes,
          FileMode mode,
          FileFlagAttrib flagsAndAttributes,
          IntPtr hTemplateFile);

        public static List<string> GetInheritedFrom(Alphaleonis.Win32.Filesystem.FileSystemInfo item, ObjectSecurity sd)
        {
            List<string> stringList = new List<string>();
            RawSecurityDescriptor securityDescriptor = new RawSecurityDescriptor(sd.GetSecurityDescriptorBinaryForm(), 0);
            if (securityDescriptor.SystemAcl != null)
            {
                int count = securityDescriptor.SystemAcl.Count;
                byte[] numArray = new byte[securityDescriptor.SystemAcl.BinaryLength];
                securityDescriptor.SystemAcl.GetBinaryForm(numArray, 0);
                try
                {
                    stringList = Win32.GetInheritedFrom(item.FullName, numArray, count, item is Alphaleonis.Win32.Filesystem.DirectoryInfo, SECURITY_INFORMATION.SACL_SECURITY_INFORMATION);
                }
                catch
                {
                    stringList = new List<string>();
                    for (int index = 0; index < count; ++index)
                        stringList.Add("unknown parent");
                }
            }
            else if (securityDescriptor.DiscretionaryAcl != null)
            {
                int count = securityDescriptor.DiscretionaryAcl.Count;
                byte[] numArray = new byte[securityDescriptor.DiscretionaryAcl.BinaryLength];
                securityDescriptor.DiscretionaryAcl.GetBinaryForm(numArray, 0);
                try
                {
                    stringList = Win32.GetInheritedFrom(item.FullName, numArray, count, item is Alphaleonis.Win32.Filesystem.DirectoryInfo, SECURITY_INFORMATION.DACL_SECURITY_INFORMATION);
                }
                catch
                {
                    stringList = new List<string>();
                    for (int index = 0; index < count; ++index)
                        stringList.Add("unknown parent");
                }
            }
            return stringList;
        }

        public static List<string> GetInheritedFrom(
          string path,
          byte[] aclBytes,
          int aceCount,
          bool isContainer,
          SECURITY_INFORMATION aclType)
        {
            List<string> stringList = new List<string>();
            path = Alphaleonis.Win32.Filesystem.Path.GetLongPath(path);
            Win32.GENERIC_MAPPING pGenericMapping = new Win32.GENERIC_MAPPING
            {
                GenericRead = 1179785U,
                GenericWrite = 1179926U,
                GenericExecute = 1179808U,
                GenericAll = 2032127U
            };
            IntPtr num1 = Marshal.AllocHGlobal(aceCount * Marshal.SizeOf(typeof(Win32.PINHERITED_FROM)));
            uint inheritanceSource = Win32.GetInheritanceSource(path, ResourceType.FileObject, aclType, isContainer, IntPtr.Zero, 0U, aclBytes, IntPtr.Zero, ref pGenericMapping, num1);
            if (inheritanceSource != 0U)
                throw new Win32Exception((int)inheritanceSource);
            for (int index = 0; index < aceCount; ++index)
            {
                Win32.PINHERITED_FROM pinheritedFrom = num1.ElementAt<Win32.PINHERITED_FROM>(index);
                stringList.Add(string.IsNullOrEmpty(pinheritedFrom.AncestorName) || !pinheritedFrom.AncestorName.StartsWith("\\\\?\\") ? pinheritedFrom.AncestorName : pinheritedFrom.AncestorName.Substring(4));
            }
            int num2 = (int)Win32.FreeInheritedFromArray(num1, (ushort)aceCount, IntPtr.Zero);
            Marshal.FreeHGlobal(num1);
            return stringList;
        }

        public int GetEffectiveAccess(
          ObjectSecurity sd,
          IdentityReference2 identity,
          string serverName,
          out bool remoteServerAvailable,
          out Exception authzException)
        {
            int num = 0;
            remoteServerAvailable = false;
            authzException = (Exception)null;
            try
            {
                GetEffectivePermissions_AuthzInitializeResourceManager(serverName, out remoteServerAvailable);
                try
                {
                    GetEffectivePermissions_AuthzInitializeContextFromSid(identity);
                    num = GetEffectivePermissions_AuthzAccessCheck(sd);
                }
                catch (Exception ex)
                {
                    authzException = ex;
                }
            }
            catch
            {
            }
            finally
            {
                GetEffectivePermissions_FreeResouces();
            }
            return num;
        }

        private void GetEffectivePermissions_AuthzInitializeResourceManager(
          string serverName,
          out bool remoteServerAvailable)
        {
            remoteServerAvailable = false;
            if (!Win32.AuthzInitializeRemoteResourceManager(SafeHGlobalHandle.AllocHGlobalStruct<Win32.AUTHZ_RPC_INIT_INFO_CLIENT>(new Win32.AUTHZ_RPC_INIT_INFO_CLIENT()
            {
                version = AuthzRpcClientVersion.V1,
                objectUuid = "9a81c2bd-a525-471d-a4ed-49907c0b23da",
                protocol = "ncacn_ip_tcp",
                server = serverName
            }).ToIntPtr(), out authzRM))
            {
                int lastWin32Error = Marshal.GetLastWin32Error();
                if (lastWin32Error != 1753)
                    throw new Win32Exception(lastWin32Error);
                if (serverName == "localhost")
                    remoteServerAvailable = true;
                if (!Win32.AuthzInitializeResourceManager(AuthzResourceManagerFlags.NO_AUDIT, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, "EffectiveAccessCheck", out authzRM))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            else
                remoteServerAvailable = true;
        }

        private void GetEffectivePermissions_AuthzInitializeContextFromSid(IdentityReference2 id)
        {
            if (Win32.AuthzInitializeContextFromSid(AuthzInitFlags.Default, id.GetBinaryForm(), authzRM, IntPtr.Zero, Win32.LUID.NullLuid, IntPtr.Zero, out userClientCtxt))
                return;
            Win32Exception win32Exception = new Win32Exception(Marshal.GetLastWin32Error());
            if (win32Exception.NativeErrorCode != 1722)
                throw win32Exception;
        }

        private int GetEffectivePermissions_AuthzAccessCheck(ObjectSecurity sd)
        {
            Win32.AUTHZ_ACCESS_REQUEST pRequest = new Win32.AUTHZ_ACCESS_REQUEST
            {
                DesiredAccess = StdAccess.MAXIMUM_ALLOWED,
                PrincipalSelfSid = (byte[])null,
                ObjectTypeList = IntPtr.Zero,
                ObjectTypeListLength = 0,
                OptionalArguments = IntPtr.Zero
            };
            Win32.AUTHZ_ACCESS_REPLY pReply = new Win32.AUTHZ_ACCESS_REPLY
            {
                ResultListLength = 1,
                SaclEvaluationResults = IntPtr.Zero,
                GrantedAccessMask = pGrantedAccess = Marshal.AllocHGlobal(4),
                Error = pErrorSecObj = Marshal.AllocHGlobal(4)
            };
            byte[] descriptorBinaryForm = sd.GetSecurityDescriptorBinaryForm();
            if (!Win32.AuthzAccessCheck(Win32.AuthzACFlags.None, userClientCtxt, ref pRequest, IntPtr.Zero, descriptorBinaryForm, (IntPtr[])null, 0U, ref pReply, IntPtr.Zero) && Marshal.GetLastWin32Error() != 0)
                throw new Win32Exception();
            return Marshal.ReadInt32(pGrantedAccess);
        }

        private void GetEffectivePermissions_FreeResouces()
        {
            Marshal.FreeHGlobal(pGrantedAccess);
            Marshal.FreeHGlobal(pErrorSecObj);
            if (!(userClientCtxt != IntPtr.Zero))
                return;
            Win32.AuthzFreeContext(userClientCtxt);
            userClientCtxt = IntPtr.Zero;
        }

        private static RawSecurityDescriptor GetRawSecurityDescriptor(
          SafeFileHandle handle,
          SecurityInformationClass infoClass)
        {
            return new RawSecurityDescriptor(Win32.GetByteSecurityDescriptor(handle, infoClass), 0);
        }

        public static byte[] GetByteSecurityDescriptor(
          SafeFileHandle handle,
          SecurityInformationClass infoClass)
        {
            IntPtr securityDescriptor = IntPtr.Zero;
            byte[] destination = new byte[0];
            try
            {
                if (Win32.GetSecurityInfo(handle, ObjectType.File, infoClass, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out securityDescriptor) != 0U)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                uint descriptorLength = Win32.GetSecurityDescriptorLength(securityDescriptor);
                destination = new byte[(int)descriptorLength];
                Marshal.Copy(securityDescriptor, destination, 0, (int)descriptorLength);
            }
            finally
            {
                Marshal.FreeHGlobal(securityDescriptor);
                IntPtr zero = IntPtr.Zero;
            }
            return destination;
        }

        private struct PINHERITED_FROM
        {
            public int GenerationGap;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string AncestorName;
        }

        private struct GENERIC_MAPPING
        {
            public uint GenericRead;
            public uint GenericWrite;
            public uint GenericExecute;
            public uint GenericAll;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct AUTHZ_RPC_INIT_INFO_CLIENT
        {
            public AuthzRpcClientVersion version;
            public string objectUuid;
            public string protocol;
            public string server;
            public string endPoint;
            public string options;
            public string serverSpn;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct LUID
        {
            public uint LowPart;
            public uint HighPart;

            public static Win32.LUID NullLuid
            {
                get
                {
                    Win32.LUID luid;
                    luid.LowPart = 0U;
                    luid.HighPart = 0U;
                    return luid;
                }
            }
        }

        internal struct AUTHZ_ACCESS_REQUEST
        {
            public StdAccess DesiredAccess;
            public byte[] PrincipalSelfSid;
            public IntPtr ObjectTypeList;
            public int ObjectTypeListLength;
            public IntPtr OptionalArguments;
        }

        internal struct AUTHZ_ACCESS_REPLY
        {
            public int ResultListLength;
            public IntPtr GrantedAccessMask;
            public IntPtr SaclEvaluationResults;
            public IntPtr Error;
        }

        internal enum AuthzACFlags : uint
        {
            None,
            NoDeepCopySD,
        }
    }
    public class FileSystemSecurity2
    {
        protected FileSecurity fileSecurityDescriptor;
        protected DirectorySecurity directorySecurityDescriptor;
        protected Alphaleonis.Win32.Filesystem.FileSystemInfo item;
        protected FileSystemSecurity sd;
        protected AccessControlSections sections;
        protected bool isFile;

        public Alphaleonis.Win32.Filesystem.FileSystemInfo Item
        {
            get => item;
            set => item = value;
        }

        public string FullName => item.FullName;

        public string Name => item.Name;

        public bool IsFile => isFile;

        public FileSystemSecurity2(Alphaleonis.Win32.Filesystem.FileSystemInfo item, AccessControlSections sections)
        {
            this.sections = sections;
            if (item is Alphaleonis.Win32.Filesystem.FileInfo)
            {
                this.item = item;
                sd = (FileSystemSecurity)((Alphaleonis.Win32.Filesystem.FileInfo)this.item).GetAccessControl(sections);
                isFile = true;
            }
            else
            {
                this.item = item;
                sd = (FileSystemSecurity)((Alphaleonis.Win32.Filesystem.DirectoryInfo)this.item).GetAccessControl(sections);
            }
        }

        public FileSystemSecurity2(Alphaleonis.Win32.Filesystem.FileSystemInfo item)
        {
            if (item is Alphaleonis.Win32.Filesystem.FileInfo)
            {
                this.item = item;
                try
                {
                    sd = (FileSystemSecurity)((Alphaleonis.Win32.Filesystem.FileInfo)this.item).GetAccessControl(AccessControlSections.All);
                }
                catch
                {
                    try
                    {
                        sd = (FileSystemSecurity)((Alphaleonis.Win32.Filesystem.FileInfo)this.item).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner | AccessControlSections.Group);
                    }
                    catch
                    {
                        sd = (FileSystemSecurity)((Alphaleonis.Win32.Filesystem.FileInfo)this.item).GetAccessControl(AccessControlSections.Access);
                    }
                }
                isFile = true;
            }
            else
            {
                this.item = item;
                try
                {
                    sd = (FileSystemSecurity)((Alphaleonis.Win32.Filesystem.DirectoryInfo)this.item).GetAccessControl(AccessControlSections.All);
                }
                catch
                {
                    try
                    {
                        sd = (FileSystemSecurity)((Alphaleonis.Win32.Filesystem.DirectoryInfo)this.item).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner | AccessControlSections.Group);
                    }
                    catch
                    {
                        sd = (FileSystemSecurity)((Alphaleonis.Win32.Filesystem.DirectoryInfo)this.item).GetAccessControl(AccessControlSections.Access);
                    }
                }
            }
        }

        public FileSystemSecurity SecurityDescriptor => sd;

        public void Write()
        {
            if (isFile)
                ((Alphaleonis.Win32.Filesystem.FileInfo)item).SetAccessControl((FileSecurity)sd);
            else
                ((Alphaleonis.Win32.Filesystem.DirectoryInfo)item).SetAccessControl((DirectorySecurity)sd);
        }

        public void Write(Alphaleonis.Win32.Filesystem.FileSystemInfo item)
        {
            if (item is Alphaleonis.Win32.Filesystem.FileInfo)
                ((Alphaleonis.Win32.Filesystem.FileInfo)item).SetAccessControl((FileSecurity)sd);
            else
                ((Alphaleonis.Win32.Filesystem.DirectoryInfo)item).SetAccessControl((DirectorySecurity)sd);
        }

        public void Write(string path)
        {
            Alphaleonis.Win32.Filesystem.FileSystemInfo fileSystemInfo;
            if (Alphaleonis.Win32.Filesystem.File.Exists(path))
                fileSystemInfo = (Alphaleonis.Win32.Filesystem.FileSystemInfo)new Alphaleonis.Win32.Filesystem.FileInfo(path);
            else
                fileSystemInfo = Alphaleonis.Win32.Filesystem.Directory.Exists(path) ? (Alphaleonis.Win32.Filesystem.FileSystemInfo)new Alphaleonis.Win32.Filesystem.DirectoryInfo(path) : throw new FileNotFoundException("File not found", path);
            Write(fileSystemInfo);
        }

        public static implicit operator FileSecurity(FileSystemSecurity2 fs2) => fs2.fileSecurityDescriptor;

        public static implicit operator FileSystemSecurity2(FileSecurity fs) => new FileSystemSecurity2((Alphaleonis.Win32.Filesystem.FileSystemInfo)new Alphaleonis.Win32.Filesystem.FileInfo(""));

        public static implicit operator DirectorySecurity(FileSystemSecurity2 fs2) => fs2.directorySecurityDescriptor;

        public static implicit operator FileSystemSecurity2(DirectorySecurity fs) => new FileSystemSecurity2((Alphaleonis.Win32.Filesystem.FileSystemInfo)new Alphaleonis.Win32.Filesystem.DirectoryInfo(""));

        public override bool Equals(object obj) => fileSecurityDescriptor == (FileSecurity)obj;

        public override int GetHashCode() => fileSecurityDescriptor.GetHashCode();

        public static void ConvertToFileSystemFlags(
          ApplyTo ApplyTo,
          out InheritanceFlags inheritanceFlags,
          out PropagationFlags propagationFlags)
        {
            inheritanceFlags = InheritanceFlags.None;
            propagationFlags = PropagationFlags.None;
            switch (ApplyTo)
            {
                case ApplyTo.ThisFolderOnly:
                    inheritanceFlags = InheritanceFlags.None;
                    propagationFlags = PropagationFlags.None;
                    break;
                case ApplyTo.ThisFolderSubfoldersAndFiles:
                    inheritanceFlags = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
                    propagationFlags = PropagationFlags.None;
                    break;
                case ApplyTo.ThisFolderAndSubfolders:
                    inheritanceFlags = InheritanceFlags.ContainerInherit;
                    propagationFlags = PropagationFlags.None;
                    break;
                case ApplyTo.ThisFolderAndFiles:
                    inheritanceFlags = InheritanceFlags.ObjectInherit;
                    propagationFlags = PropagationFlags.None;
                    break;
                case ApplyTo.SubfoldersAndFilesOnly:
                    inheritanceFlags = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
                    propagationFlags = PropagationFlags.InheritOnly;
                    break;
                case ApplyTo.SubfoldersOnly:
                    inheritanceFlags = InheritanceFlags.ContainerInherit;
                    propagationFlags = PropagationFlags.InheritOnly;
                    break;
                case ApplyTo.FilesOnly:
                    inheritanceFlags = InheritanceFlags.ObjectInherit;
                    propagationFlags = PropagationFlags.InheritOnly;
                    break;
                case ApplyTo.ThisFolderSubfoldersAndFilesOneLevel:
                    inheritanceFlags = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
                    propagationFlags = PropagationFlags.NoPropagateInherit;
                    break;
                case ApplyTo.ThisFolderAndSubfoldersOneLevel:
                    inheritanceFlags = InheritanceFlags.ContainerInherit;
                    propagationFlags = PropagationFlags.NoPropagateInherit;
                    break;
                case ApplyTo.ThisFolderAndFilesOneLevel:
                    inheritanceFlags = InheritanceFlags.ObjectInherit;
                    propagationFlags = PropagationFlags.NoPropagateInherit;
                    break;
                case ApplyTo.SubfoldersAndFilesOnlyOneLevel:
                    inheritanceFlags = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
                    propagationFlags = PropagationFlags.NoPropagateInherit | PropagationFlags.InheritOnly;
                    break;
                case ApplyTo.SubfoldersOnlyOneLevel:
                    inheritanceFlags = InheritanceFlags.ContainerInherit;
                    propagationFlags = PropagationFlags.NoPropagateInherit | PropagationFlags.InheritOnly;
                    break;
                case ApplyTo.FilesOnlyOneLevel:
                    inheritanceFlags = InheritanceFlags.ObjectInherit;
                    propagationFlags = PropagationFlags.NoPropagateInherit | PropagationFlags.InheritOnly;
                    break;
            }
        }

        public static ApplyTo ConvertToApplyTo(
          InheritanceFlags InheritanceFlags,
          PropagationFlags PropagationFlags)
        {
            if (InheritanceFlags == InheritanceFlags.ObjectInherit & PropagationFlags == PropagationFlags.InheritOnly)
                return ApplyTo.FilesOnly;
            if (InheritanceFlags == (InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit) & PropagationFlags == PropagationFlags.InheritOnly)
                return ApplyTo.SubfoldersAndFilesOnly;
            if (InheritanceFlags == InheritanceFlags.ContainerInherit & PropagationFlags == PropagationFlags.InheritOnly)
                return ApplyTo.SubfoldersOnly;
            if (InheritanceFlags == InheritanceFlags.ObjectInherit & PropagationFlags == PropagationFlags.None)
                return ApplyTo.ThisFolderAndFiles;
            if (InheritanceFlags == InheritanceFlags.ContainerInherit & PropagationFlags == PropagationFlags.None)
                return ApplyTo.ThisFolderAndSubfolders;
            if (InheritanceFlags == InheritanceFlags.None & PropagationFlags == PropagationFlags.None)
                return ApplyTo.ThisFolderOnly;
            if (InheritanceFlags == (InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit) & PropagationFlags == PropagationFlags.None)
                return ApplyTo.ThisFolderSubfoldersAndFiles;
            if (InheritanceFlags == (InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit) & PropagationFlags == PropagationFlags.NoPropagateInherit)
                return ApplyTo.ThisFolderSubfoldersAndFilesOneLevel;
            if (InheritanceFlags == InheritanceFlags.ContainerInherit & PropagationFlags == PropagationFlags.NoPropagateInherit)
                return ApplyTo.ThisFolderAndSubfoldersOneLevel;
            if (InheritanceFlags == InheritanceFlags.ObjectInherit & PropagationFlags == PropagationFlags.NoPropagateInherit)
                return ApplyTo.ThisFolderAndFilesOneLevel;
            if (InheritanceFlags == (InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit) & PropagationFlags == (PropagationFlags.NoPropagateInherit | PropagationFlags.InheritOnly))
                return ApplyTo.SubfoldersAndFilesOnlyOneLevel;
            if (InheritanceFlags == InheritanceFlags.ContainerInherit & PropagationFlags == (PropagationFlags.NoPropagateInherit | PropagationFlags.InheritOnly))
                return ApplyTo.SubfoldersOnlyOneLevel;
            if (InheritanceFlags == InheritanceFlags.ObjectInherit & PropagationFlags == (PropagationFlags.NoPropagateInherit | PropagationFlags.InheritOnly))
                return ApplyTo.FilesOnlyOneLevel;
            throw new RightsConverionException("The combination of InheritanceFlags and PropagationFlags could not be translated");
        }

        public static FileSystemRights MapGenericRightsToFileSystemRights(
          uint originalRights)
        {
            try
            {
                return !(Enum.Parse(typeof(FileSystemRights), originalRights.ToString()).ToString() == originalRights.ToString()) ? (FileSystemRights)originalRights : throw new ArgumentOutOfRangeException();
            }
            catch (Exception ex)
            {
                FileSystemRights fileSystemRights1 = (FileSystemRights)0;
                if (Convert.ToBoolean(originalRights & 536870912U))
                {
                    fileSystemRights1 |= FileSystemRights.ExecuteFile | FileSystemRights.ReadAttributes | FileSystemRights.ReadPermissions | FileSystemRights.Synchronize;
                    originalRights ^= 536870912U;
                }
                if (Convert.ToBoolean(originalRights & 2147483648U))
                {
                    fileSystemRights1 |= FileSystemRights.Read | FileSystemRights.Synchronize;
                    originalRights ^= 2147483648U;
                }
                if (Convert.ToBoolean(originalRights & 1073741824U))
                {
                    fileSystemRights1 |= FileSystemRights.Write | FileSystemRights.ReadPermissions | FileSystemRights.Synchronize;
                    originalRights ^= 1073741824U;
                }
                if (Convert.ToBoolean(originalRights & 268435456U))
                {
                    fileSystemRights1 |= FileSystemRights.FullControl;
                    originalRights ^= 268435456U;
                }
                FileSystemRights fileSystemRights2 = (FileSystemRights)Enum.Parse(typeof(FileSystemRights), originalRights.ToString());
                return fileSystemRights1 | fileSystemRights2;
            }
        }
    }

    public class FileSystemAccessRule2
    {
        private FileSystemAccessRule fileSystemAccessRule;
        private string fullName;
        private bool inheritanceEnabled;
        private string inheritedFrom;

        public string Name => System.IO.Path.GetFileName(fullName);

        public string FullName
        {
            get => fullName;
            set => fullName = value;
        }

        public bool InheritanceEnabled
        {
            get => inheritanceEnabled;
            set => inheritanceEnabled = value;
        }

        public string InheritedFrom
        {
            get => inheritedFrom;
            set => inheritedFrom = value;
        }

        public AccessControlType AccessControlType => fileSystemAccessRule.AccessControlType;

        public FileSystemRights2 AccessRights => (FileSystemRights2)fileSystemAccessRule.FileSystemRights;

        public IdentityReference2 Account => (IdentityReference2)fileSystemAccessRule.IdentityReference;

        public InheritanceFlags InheritanceFlags => fileSystemAccessRule.InheritanceFlags;

        public bool IsInherited => fileSystemAccessRule.IsInherited;

        public PropagationFlags PropagationFlags => fileSystemAccessRule.PropagationFlags;

        public FileSystemAccessRule2(FileSystemAccessRule fileSystemAccessRule) => this.fileSystemAccessRule = fileSystemAccessRule;

        public FileSystemAccessRule2(FileSystemAccessRule fileSystemAccessRule, Alphaleonis.Win32.Filesystem.FileSystemInfo item)
        {
            this.fileSystemAccessRule = fileSystemAccessRule;
            fullName = item.FullName;
        }

        public FileSystemAccessRule2(FileSystemAccessRule fileSystemAccessRule, string path) => this.fileSystemAccessRule = fileSystemAccessRule;

        public static implicit operator FileSystemAccessRule(
          FileSystemAccessRule2 ace2)
        {
            return ace2.fileSystemAccessRule;
        }

        public static implicit operator FileSystemAccessRule2(
          FileSystemAccessRule ace)
        {
            return new FileSystemAccessRule2(ace);
        }

        public override bool Equals(object obj) => fileSystemAccessRule == (FileSystemAccessRule)obj;

        public override int GetHashCode() => fileSystemAccessRule.GetHashCode();

        public override string ToString() => string.Format("{0} '{1}' ({2})", (object)AccessControlType.ToString()[0], (object)Account.AccountName, (object)AccessRights.ToString());

        public SimpleFileSystemAccessRule ToSimpleFileSystemAccessRule2() => new SimpleFileSystemAccessRule(fullName, Account, AccessRights);

        public static void RemoveFileSystemAccessRuleAll(
          FileSystemSecurity2 sd,
          List<IdentityReference2> accounts = null)
        {
            AuthorizationRuleCollection accessRules = sd.SecurityDescriptor.GetAccessRules(true, false, typeof(SecurityIdentifier));
            if (accounts != null)
                accessRules.OfType<FileSystemAccessRule>().Where<FileSystemAccessRule>((Func<FileSystemAccessRule, bool>)(ace => accounts.Where<IdentityReference2>((Func<IdentityReference2, bool>)(account => account == (IdentityReference2)ace.IdentityReference)).Count<IdentityReference2>() > 1));
            foreach (FileSystemAccessRule rule in (ReadOnlyCollectionBase)accessRules)
                sd.SecurityDescriptor.RemoveAccessRuleSpecific(rule);
        }

        public static void RemoveFileSystemAccessRuleAll(
          Alphaleonis.Win32.Filesystem.FileSystemInfo item,
          List<IdentityReference2> accounts = null)
        {
            FileSystemSecurity2 sd = new FileSystemSecurity2(item);
            FileSystemAccessRule2.RemoveFileSystemAccessRuleAll(sd, accounts);
            sd.Write();
        }

        public static void RemoveFileSystemAccessRule(
          Alphaleonis.Win32.Filesystem.FileSystemInfo item,
          IdentityReference2 account,
          FileSystemRights2 rights,
          AccessControlType type,
          InheritanceFlags inheritanceFlags,
          PropagationFlags propagationFlags,
          bool removeSpecific = false)
        {
            if (type == AccessControlType.Allow)
                rights |= FileSystemRights2.Synchronize;
            if ((Alphaleonis.Win32.Filesystem.FileSystemInfo)(item as Alphaleonis.Win32.Filesystem.FileInfo) != (Alphaleonis.Win32.Filesystem.FileSystemInfo)null)
            {
                Alphaleonis.Win32.Filesystem.FileInfo fileInfo = (Alphaleonis.Win32.Filesystem.FileInfo)item;
                FileSecurity accessControl = fileInfo.GetAccessControl(AccessControlSections.Access);
                FileSystemAccessRule rule = (FileSystemAccessRule)accessControl.AccessRuleFactory((IdentityReference)account, (int)rights, false, inheritanceFlags, propagationFlags, type);
                if (removeSpecific)
                    accessControl.RemoveAccessRuleSpecific(rule);
                else
                    accessControl.RemoveAccessRule(rule);
                fileInfo.SetAccessControl(accessControl);
            }
            else
            {
                Alphaleonis.Win32.Filesystem.DirectoryInfo directoryInfo = (Alphaleonis.Win32.Filesystem.DirectoryInfo)item;
                DirectorySecurity accessControl = directoryInfo.GetAccessControl(AccessControlSections.Access);
                FileSystemAccessRule rule = (FileSystemAccessRule)accessControl.AccessRuleFactory((IdentityReference)account, (int)rights, false, inheritanceFlags, propagationFlags, type);
                if (removeSpecific)
                    accessControl.RemoveAccessRuleSpecific(rule);
                else
                    accessControl.RemoveAccessRule(rule);
                directoryInfo.SetAccessControl(accessControl);
            }
        }

        public static void RemoveFileSystemAccessRule(
          Alphaleonis.Win32.Filesystem.FileSystemInfo item,
          List<IdentityReference2> accounts,
          FileSystemRights2 rights,
          AccessControlType type,
          InheritanceFlags inheritanceFlags,
          PropagationFlags propagationFlags,
          bool removeSpecific = false)
        {
            foreach (IdentityReference2 account in accounts)
                FileSystemAccessRule2.RemoveFileSystemAccessRule(item, account, rights, type, inheritanceFlags, propagationFlags, removeSpecific);
        }

        public static void RemoveFileSystemAccessRule(
          string path,
          IdentityReference2 account,
          FileSystemRights2 rights,
          AccessControlType type,
          InheritanceFlags inheritanceFlags,
          PropagationFlags propagationFlags,
          bool removeSpecific = false)
        {
            if (Alphaleonis.Win32.Filesystem.File.Exists(path))
                FileSystemAccessRule2.RemoveFileSystemAccessRule((Alphaleonis.Win32.Filesystem.FileSystemInfo)new Alphaleonis.Win32.Filesystem.FileInfo(path), account, rights, type, inheritanceFlags, propagationFlags, removeSpecific);
            else
                FileSystemAccessRule2.RemoveFileSystemAccessRule((Alphaleonis.Win32.Filesystem.FileSystemInfo)new Alphaleonis.Win32.Filesystem.DirectoryInfo(path), account, rights, type, inheritanceFlags, propagationFlags, removeSpecific);
        }

        public static void RemoveFileSystemAccessRule(
          string path,
          List<IdentityReference2> account,
          FileSystemRights2 rights,
          AccessControlType type,
          InheritanceFlags inheritanceFlags,
          PropagationFlags propagationFlags,
          bool removeSpecific = false)
        {
            if (Alphaleonis.Win32.Filesystem.File.Exists(path))
                FileSystemAccessRule2.RemoveFileSystemAccessRule((Alphaleonis.Win32.Filesystem.FileSystemInfo)new Alphaleonis.Win32.Filesystem.FileInfo(path), account, rights, type, inheritanceFlags, propagationFlags, removeSpecific);
            else
                FileSystemAccessRule2.RemoveFileSystemAccessRule((Alphaleonis.Win32.Filesystem.FileSystemInfo)new Alphaleonis.Win32.Filesystem.DirectoryInfo(path), account, rights, type, inheritanceFlags, propagationFlags, removeSpecific);
        }

        public static void RemoveFileSystemAccessRule(
          Alphaleonis.Win32.Filesystem.FileSystemInfo item,
          FileSystemAccessRule ace,
          bool removeSpecific = false)
        {
            if ((Alphaleonis.Win32.Filesystem.FileSystemInfo)(item as Alphaleonis.Win32.Filesystem.FileInfo) != (Alphaleonis.Win32.Filesystem.FileSystemInfo)null)
            {
                Alphaleonis.Win32.Filesystem.FileInfo fileInfo = (Alphaleonis.Win32.Filesystem.FileInfo)item;
                FileSecurity accessControl = fileInfo.GetAccessControl(AccessControlSections.Access);
                if (removeSpecific)
                    accessControl.RemoveAccessRuleSpecific(ace);
                else
                    accessControl.RemoveAccessRule(ace);
                fileInfo.SetAccessControl(accessControl);
            }
            else
            {
                Alphaleonis.Win32.Filesystem.DirectoryInfo directoryInfo = (Alphaleonis.Win32.Filesystem.DirectoryInfo)item;
                DirectorySecurity accessControl = directoryInfo.GetAccessControl(AccessControlSections.Access);
                if (removeSpecific)
                    accessControl.RemoveAccessRuleSpecific(ace);
                else
                    accessControl.RemoveAccessRule(ace);
                directoryInfo.SetAccessControl(accessControl);
            }
        }

        public static FileSystemAccessRule2 RemoveFileSystemAccessRule(
          FileSystemSecurity2 sd,
          IdentityReference2 account,
          FileSystemRights2 rights,
          AccessControlType type,
          InheritanceFlags inheritanceFlags,
          PropagationFlags propagationFlags,
          bool removeSpecific = false)
        {
            if (type == AccessControlType.Allow)
                rights |= FileSystemRights2.Synchronize;
            FileSystemAccessRule rule = (FileSystemAccessRule)sd.SecurityDescriptor.AccessRuleFactory((IdentityReference)account, (int)rights, false, inheritanceFlags, propagationFlags, type);
            if (sd.IsFile)
            {
                if (removeSpecific)
                    sd.SecurityDescriptor.RemoveAccessRuleSpecific(rule);
                else
                    sd.SecurityDescriptor.RemoveAccessRule(rule);
            }
            else if (removeSpecific)
                sd.SecurityDescriptor.RemoveAccessRuleSpecific(rule);
            else
                sd.SecurityDescriptor.RemoveAccessRule(rule);
            return (FileSystemAccessRule2)rule;
        }

        public static IEnumerable<FileSystemAccessRule2> RemoveFileSystemAccessRule(
          FileSystemSecurity2 sd,
          List<IdentityReference2> accounts,
          FileSystemRights2 rights,
          AccessControlType type,
          InheritanceFlags inheritanceFlags,
          PropagationFlags propagationFlags,
          bool removeSpecific = false)
        {
            List<FileSystemAccessRule2> systemAccessRule2List = new List<FileSystemAccessRule2>();
            foreach (IdentityReference2 account in accounts)
                systemAccessRule2List.Add(FileSystemAccessRule2.RemoveFileSystemAccessRule(sd, account, rights, type, inheritanceFlags, propagationFlags));
            return (IEnumerable<FileSystemAccessRule2>)systemAccessRule2List;
        }

        public static IEnumerable<FileSystemAccessRule2> GetFileSystemAccessRules(
          Alphaleonis.Win32.Filesystem.FileSystemInfo item,
          bool includeExplicit,
          bool includeInherited,
          bool getInheritedFrom = false)
        {
            return FileSystemAccessRule2.GetFileSystemAccessRules(new FileSystemSecurity2(item, AccessControlSections.Access), includeExplicit, includeInherited, getInheritedFrom);
        }

        public static IEnumerable<FileSystemAccessRule2> GetFileSystemAccessRules(
          FileSystemSecurity2 sd,
          bool includeExplicit,
          bool includeInherited,
          bool getInheritedFrom = false)
        {
            List<FileSystemAccessRule2> systemAccessRule2List = new List<FileSystemAccessRule2>();
            List<string> stringList = (List<string>)null;
            if (getInheritedFrom)
                stringList = Win32.GetInheritedFrom(sd.Item, (ObjectSecurity)sd.SecurityDescriptor);
            int index = 0;
            foreach (FileSystemAccessRule fileSystemAccessRule in !sd.IsFile ? (ReadOnlyCollectionBase)sd.SecurityDescriptor.GetAccessRules(includeExplicit, includeInherited, typeof(SecurityIdentifier)) : (ReadOnlyCollectionBase)sd.SecurityDescriptor.GetAccessRules(includeExplicit, includeInherited, typeof(SecurityIdentifier)))
            {
                FileSystemAccessRule2 systemAccessRule2 = new FileSystemAccessRule2(fileSystemAccessRule)
                {
                    FullName = sd.Item.FullName,
                    InheritanceEnabled = !sd.SecurityDescriptor.AreAccessRulesProtected
                };
                if (getInheritedFrom)
                {
                    systemAccessRule2.inheritedFrom = string.IsNullOrEmpty(stringList[index]) ? "" : stringList[index].Substring(0, stringList[index].Length - 1);
                    ++index;
                }
                systemAccessRule2List.Add(systemAccessRule2);
            }
            return (IEnumerable<FileSystemAccessRule2>)systemAccessRule2List;
        }

        public static IEnumerable<FileSystemAccessRule2> GetFileSystemAccessRules(
          string path,
          bool includeExplicit,
          bool includeInherited,
          bool getInheritedFrom = false)
        {
            return Alphaleonis.Win32.Filesystem.File.Exists(path) ? FileSystemAccessRule2.GetFileSystemAccessRules((Alphaleonis.Win32.Filesystem.FileSystemInfo)new Alphaleonis.Win32.Filesystem.FileInfo(path), includeExplicit, includeInherited, getInheritedFrom) : FileSystemAccessRule2.GetFileSystemAccessRules((Alphaleonis.Win32.Filesystem.FileSystemInfo)new Alphaleonis.Win32.Filesystem.DirectoryInfo(path), includeExplicit, includeInherited, getInheritedFrom);
        }

        public static FileSystemAccessRule2 AddFileSystemAccessRule(
          FileSystemSecurity2 sd,
          IdentityReference2 account,
          FileSystemRights2 rights,
          AccessControlType type,
          InheritanceFlags inheritanceFlags,
          PropagationFlags propagationFlags)
        {
            if (type == AccessControlType.Allow)
                rights |= FileSystemRights2.Synchronize;
            FileSystemAccessRule rule;
            if (sd.IsFile)
            {
                rule = (FileSystemAccessRule)sd.SecurityDescriptor.AccessRuleFactory((IdentityReference)account, (int)rights, false, InheritanceFlags.None, PropagationFlags.None, type);
                sd.SecurityDescriptor.AddAccessRule(rule);
            }
            else
            {
                rule = (FileSystemAccessRule)sd.SecurityDescriptor.AccessRuleFactory((IdentityReference)account, (int)rights, false, inheritanceFlags, propagationFlags, type);
                sd.SecurityDescriptor.AddAccessRule(rule);
            }
            return (FileSystemAccessRule2)rule;
        }

        public static FileSystemAccessRule2 AddFileSystemAccessRule(
          Alphaleonis.Win32.Filesystem.FileSystemInfo item,
          IdentityReference2 account,
          FileSystemRights2 rights,
          AccessControlType type,
          InheritanceFlags inheritanceFlags,
          PropagationFlags propagationFlags)
        {
            if (type == AccessControlType.Allow)
                rights |= FileSystemRights2.Synchronize;
            FileSystemSecurity2 sd = new FileSystemSecurity2(item);
            FileSystemAccessRule2 systemAccessRule2 = FileSystemAccessRule2.AddFileSystemAccessRule(sd, account, rights, type, inheritanceFlags, propagationFlags);
            sd.Write();
            return systemAccessRule2;
        }

        public static IEnumerable<FileSystemAccessRule2> AddFileSystemAccessRule(
          Alphaleonis.Win32.Filesystem.FileSystemInfo item,
          List<IdentityReference2> accounts,
          FileSystemRights2 rights,
          AccessControlType type,
          InheritanceFlags inheritanceFlags,
          PropagationFlags propagationFlags)
        {
            List<FileSystemAccessRule2> systemAccessRule2List = new List<FileSystemAccessRule2>();
            foreach (IdentityReference2 account in accounts)
                systemAccessRule2List.Add(FileSystemAccessRule2.AddFileSystemAccessRule(item, account, rights, type, inheritanceFlags, propagationFlags));
            return (IEnumerable<FileSystemAccessRule2>)systemAccessRule2List;
        }

        public static IEnumerable<FileSystemAccessRule2> AddFileSystemAccessRule(
          FileSystemSecurity2 sd,
          List<IdentityReference2> accounts,
          FileSystemRights2 rights,
          AccessControlType type,
          InheritanceFlags inheritanceFlags,
          PropagationFlags propagationFlags)
        {
            List<FileSystemAccessRule2> systemAccessRule2List = new List<FileSystemAccessRule2>();
            foreach (IdentityReference2 account in accounts)
                systemAccessRule2List.Add(FileSystemAccessRule2.AddFileSystemAccessRule(sd, account, rights, type, inheritanceFlags, propagationFlags));
            return (IEnumerable<FileSystemAccessRule2>)systemAccessRule2List;
        }

        public static FileSystemAccessRule2 AddFileSystemAccessRule(
          string path,
          IdentityReference2 account,
          FileSystemRights2 rights,
          AccessControlType type,
          InheritanceFlags inheritanceFlags,
          PropagationFlags propagationFlags)
        {
            if (type == AccessControlType.Allow)
                rights |= FileSystemRights2.Synchronize;
            return (FileSystemAccessRule2)(!Alphaleonis.Win32.Filesystem.File.Exists(path) ? (FileSystemAccessRule)FileSystemAccessRule2.AddFileSystemAccessRule((Alphaleonis.Win32.Filesystem.FileSystemInfo)new Alphaleonis.Win32.Filesystem.DirectoryInfo(path), account, rights, type, inheritanceFlags, propagationFlags) : (FileSystemAccessRule)FileSystemAccessRule2.AddFileSystemAccessRule((Alphaleonis.Win32.Filesystem.FileSystemInfo)new Alphaleonis.Win32.Filesystem.FileInfo(path), account, rights, type, inheritanceFlags, propagationFlags));
        }

        public static IEnumerable<FileSystemAccessRule2> AddFileSystemAccessRule(
          string path,
          List<IdentityReference2> accounts,
          FileSystemRights2 rights,
          AccessControlType type,
          InheritanceFlags inheritanceFlags,
          PropagationFlags propagationFlags)
        {
            if (type == AccessControlType.Allow)
                rights |= FileSystemRights2.Synchronize;
            if (Alphaleonis.Win32.Filesystem.File.Exists(path))
            {
                Alphaleonis.Win32.Filesystem.FileInfo item = new Alphaleonis.Win32.Filesystem.FileInfo(path);
                foreach (IdentityReference2 account in accounts)
                    yield return FileSystemAccessRule2.AddFileSystemAccessRule((Alphaleonis.Win32.Filesystem.FileSystemInfo)item, account, rights, type, inheritanceFlags, propagationFlags);
                item = (Alphaleonis.Win32.Filesystem.FileInfo)null;
            }
            else
            {
                Alphaleonis.Win32.Filesystem.DirectoryInfo item = new Alphaleonis.Win32.Filesystem.DirectoryInfo(path);
                foreach (IdentityReference2 account in accounts)
                    yield return FileSystemAccessRule2.AddFileSystemAccessRule((Alphaleonis.Win32.Filesystem.FileSystemInfo)item, account, rights, type, inheritanceFlags, propagationFlags);
                item = (Alphaleonis.Win32.Filesystem.DirectoryInfo)null;
            }
        }

        public static void AddFileSystemAccessRule(FileSystemAccessRule2 rule) => FileSystemAccessRule2.AddFileSystemAccessRule(rule.fullName, rule.Account, rule.AccessRights, rule.AccessControlType, rule.InheritanceFlags, rule.PropagationFlags);
    }

    internal class SafeAuthzRMHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeAuthzRMHandle()
          : base(true)
        {
        }

        private SafeAuthzRMHandle(IntPtr handle)
          : base(true)
        {
            SetHandle(handle);
        }

        public static SafeAuthzRMHandle InvalidHandle => new SafeAuthzRMHandle(IntPtr.Zero);

        protected override bool ReleaseHandle() => SafeAuthzRMHandle.NativeMethods.AuthzFreeResourceManager(handle);

        private static class NativeMethods
        {
            [SuppressUnmanagedCodeSecurity]
            [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
            [DllImport("authz.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool AuthzFreeResourceManager(IntPtr handle);
        }
    }

    public class RightsConverionException : Exception
    {
        public RightsConverionException(string Message)
          : base(Message)
        {
        }
    }

    [Flags]
    internal enum FileFlagAttrib : uint
    {
        BackupSemantics = 33554432, // 0x02000000
    }

    internal enum AuthzRpcClientVersion : ushort
    {
        V1 = 1,
    }

    public class SimpleFileSystemAccessRule
    {
        private string fullName;
        private IdentityReference2 identity;
        private FileSystemRights2 accessRights;
        private AccessControlType type;

        public AccessControlType AccessControlType
        {
            get => type;
            set => type = value;
        }

        public string FullName => fullName;

        public string Name => Alphaleonis.Win32.Filesystem.Path.GetFileName(fullName);

        public IdentityReference2 Identity => identity;

        public SimpleFileSystemAccessRights AccessRights
        {
            get
            {
                SimpleFileSystemAccessRights systemAccessRights = SimpleFileSystemAccessRights.None;
                if ((accessRights & FileSystemRights2.Read) == FileSystemRights2.Read)
                    systemAccessRights |= SimpleFileSystemAccessRights.Read;
                if ((accessRights & FileSystemRights2.CreateFiles) == FileSystemRights2.CreateFiles)
                    systemAccessRights |= SimpleFileSystemAccessRights.Write;
                if ((accessRights & FileSystemRights2.CreateDirectories) == FileSystemRights2.CreateDirectories)
                    systemAccessRights |= SimpleFileSystemAccessRights.Write;
                if ((accessRights & FileSystemRights2.ReadExtendedAttributes) == FileSystemRights2.ReadExtendedAttributes)
                    systemAccessRights |= SimpleFileSystemAccessRights.Read;
                if ((accessRights & FileSystemRights2.WriteExtendedAttributes) == FileSystemRights2.WriteExtendedAttributes)
                    systemAccessRights |= SimpleFileSystemAccessRights.Write;
                if ((accessRights & FileSystemRights2.ExecuteFile) == FileSystemRights2.ExecuteFile)
                    systemAccessRights |= SimpleFileSystemAccessRights.Read;
                if ((accessRights & FileSystemRights2.DeleteSubdirectoriesAndFiles) == FileSystemRights2.DeleteSubdirectoriesAndFiles)
                    systemAccessRights |= SimpleFileSystemAccessRights.Delete;
                if ((accessRights & FileSystemRights2.ReadAttributes) == FileSystemRights2.ReadAttributes)
                    systemAccessRights |= SimpleFileSystemAccessRights.Read;
                if ((accessRights & FileSystemRights2.WriteAttributes) == FileSystemRights2.WriteAttributes)
                    systemAccessRights |= SimpleFileSystemAccessRights.Write;
                if ((accessRights & FileSystemRights2.Delete) == FileSystemRights2.Delete)
                    systemAccessRights |= SimpleFileSystemAccessRights.Delete;
                if ((accessRights & FileSystemRights2.ReadPermissions) == FileSystemRights2.ReadPermissions)
                    systemAccessRights |= SimpleFileSystemAccessRights.Read;
                if ((accessRights & FileSystemRights2.ChangePermissions) == FileSystemRights2.ChangePermissions)
                    systemAccessRights |= SimpleFileSystemAccessRights.Write;
                if ((accessRights & FileSystemRights2.TakeOwnership) == FileSystemRights2.TakeOwnership)
                    systemAccessRights |= SimpleFileSystemAccessRights.Write;
                if ((accessRights & FileSystemRights2.Synchronize) == FileSystemRights2.Synchronize)
                    systemAccessRights |= SimpleFileSystemAccessRights.Read;
                if ((accessRights & FileSystemRights2.FullControl) == FileSystemRights2.FullControl)
                    systemAccessRights = SimpleFileSystemAccessRights.Read | SimpleFileSystemAccessRights.Write | SimpleFileSystemAccessRights.Delete;
                if ((accessRights & FileSystemRights2.GenericRead) == FileSystemRights2.GenericRead)
                    systemAccessRights |= SimpleFileSystemAccessRights.Read;
                if ((accessRights & FileSystemRights2.GenericWrite) == FileSystemRights2.GenericWrite)
                    systemAccessRights |= SimpleFileSystemAccessRights.Write;
                if ((accessRights & FileSystemRights2.GenericExecute) == FileSystemRights2.GenericExecute)
                    systemAccessRights |= SimpleFileSystemAccessRights.Read;
                if ((accessRights & FileSystemRights2.GenericAll) == FileSystemRights2.GenericAll)
                    systemAccessRights = SimpleFileSystemAccessRights.Read | SimpleFileSystemAccessRights.Write | SimpleFileSystemAccessRights.Delete;
                return systemAccessRights;
            }
        }

        public SimpleFileSystemAccessRule(
          string Path,
          IdentityReference2 account,
          FileSystemRights2 access)
        {
            fullName = Path;
            accessRights = access;
            identity = account;
        }

        public override bool Equals(object obj) => obj is SimpleFileSystemAccessRule systemAccessRule && AccessRights == systemAccessRule.AccessRights && Identity == systemAccessRule.Identity && AccessControlType == systemAccessRule.AccessControlType;

        public override int GetHashCode() => Identity.GetHashCode() | AccessRights.GetHashCode() | AccessControlType.GetHashCode();
    }

    [Flags]
    internal enum AuthzResourceManagerFlags : uint
    {
        NO_AUDIT = 1,
    }

    [Flags]
    internal enum AuthzInitFlags : uint
    {
        Default = 0,
        SkipTokenGroups = 2,
        RequireS4ULogon = 4,
        ComputePrivileges = 8,
    }

    [Flags]
    internal enum SecurityInformationClass : uint
    {
        Owner = 1,
        Group = 2,
        Dacl = 4,
        Sacl = 8,
        Label = 16, // 0x00000010
        Attribute = 32, // 0x00000020
        Scope = 64, // 0x00000040
    }

    [Flags]
    public enum FileSystemRights2 : uint
    {
        None = 0,
        ListDirectory = 1,
        ReadData = ListDirectory, // 0x00000001
        CreateFiles = 2,
        CreateDirectories = 4,
        AppendData = CreateDirectories, // 0x00000004
        ReadExtendedAttributes = 8,
        WriteExtendedAttributes = 16, // 0x00000010
        ExecuteFile = 32, // 0x00000020
        Traverse = ExecuteFile, // 0x00000020
        DeleteSubdirectoriesAndFiles = 64, // 0x00000040
        ReadAttributes = 128, // 0x00000080
        WriteAttributes = 256, // 0x00000100
        Write = WriteAttributes | WriteExtendedAttributes | AppendData | CreateFiles, // 0x00000116
        Delete = 65536, // 0x00010000
        ReadPermissions = 131072, // 0x00020000
        Read = ReadPermissions | ReadAttributes | ReadExtendedAttributes | ReadData, // 0x00020089
        ReadAndExecute = Read | Traverse, // 0x000200A9
        Modify = ReadAndExecute | Delete | Write, // 0x000301BF
        ChangePermissions = 262144, // 0x00040000
        TakeOwnership = 524288, // 0x00080000
        Synchronize = 1048576, // 0x00100000
        FullControl = Synchronize | TakeOwnership | ChangePermissions | Modify | DeleteSubdirectoriesAndFiles, // 0x001F01FF
        GenericRead = 2147483648, // 0x80000000
        GenericWrite = 1073741824, // 0x40000000
        GenericExecute = 536870912, // 0x20000000
        GenericAll = 268435456, // 0x10000000
    }

    [Flags]
    public enum SimpleFileSystemAccessRights
    {
        None = 0,
        Read = 1,
        Write = 2,
        Delete = 4,
    }

    internal enum SECURITY_INFORMATION
    {
        OWNER_SECURITY_INFORMATION = 1,
        GROUP_SECURITY_INFORMATION = 2,
        DACL_SECURITY_INFORMATION = 4,
        SACL_SECURITY_INFORMATION = 8,
    }

    [Flags]
    internal enum StdAccess : uint
    {
        None = 0,
        SYNCHRONIZE = 1048576, // 0x00100000
        STANDARD_RIGHTS_REQUIRED = 983040, // 0x000F0000
        MAXIMUM_ALLOWED = 33554432, // 0x02000000
    }

    internal enum ObjectType : uint
    {
        File = 1,
    }

    public enum ApplyTo
    {
        ThisFolderOnly,
        ThisFolderSubfoldersAndFiles,
        ThisFolderAndSubfolders,
        ThisFolderAndFiles,
        SubfoldersAndFilesOnly,
        SubfoldersOnly,
        FilesOnly,
        ThisFolderSubfoldersAndFilesOneLevel,
        ThisFolderAndSubfoldersOneLevel,
        ThisFolderAndFilesOneLevel,
        SubfoldersAndFilesOnlyOneLevel,
        SubfoldersOnlyOneLevel,
        FilesOnlyOneLevel,
    }

    internal sealed class SafeHGlobalHandle : IDisposable
    {
        private List<SafeHGlobalHandle> references;
        private IntPtr pointer;

        private SafeHGlobalHandle() => pointer = IntPtr.Zero;

        private SafeHGlobalHandle(IntPtr handle) => pointer = handle;

        ~SafeHGlobalHandle() => Dispose();

        public static SafeHGlobalHandle InvalidHandle => new SafeHGlobalHandle(IntPtr.Zero);

        public void AddSubReference(IEnumerable<SafeHGlobalHandle> children)
        {
            if (references == null)
                references = new List<SafeHGlobalHandle>();
            references.AddRange(children);
        }

        public static SafeHGlobalHandle AllocHGlobal(IntPtr[] values)
        {
            SafeHGlobalHandle safeHglobalHandle = SafeHGlobalHandle.AllocHGlobal(IntPtr.Size * values.Length);
            Marshal.Copy(values, 0, safeHglobalHandle.pointer, values.Length);
            return safeHglobalHandle;
        }

        public static SafeHGlobalHandle AllocHGlobalStruct<T>(T obj) where T : struct
        {
            SafeHGlobalHandle safeHglobalHandle = SafeHGlobalHandle.AllocHGlobal(Marshal.SizeOf(typeof(T)));
            Marshal.StructureToPtr((object)obj, safeHglobalHandle.pointer, false);
            return safeHglobalHandle;
        }

        public static SafeHGlobalHandle AllocHGlobal<T>(ICollection<T> values) where T : struct => SafeHGlobalHandle.AllocHGlobal<T>(0, (IEnumerable<T>)values, values.Count);

        public static SafeHGlobalHandle AllocHGlobal<T>(
          int prefixBytes,
          IEnumerable<T> values,
          int count)
          where T : struct
        {
            SafeHGlobalHandle safeHglobalHandle = SafeHGlobalHandle.AllocHGlobal(prefixBytes + Marshal.SizeOf(typeof(T)) * count);
            IntPtr ptr = new IntPtr(safeHglobalHandle.pointer.ToInt32() + prefixBytes);
            foreach (T obj in values)
            {
                Marshal.StructureToPtr((object)obj, ptr, false);
                ptr.Increment<T>();
            }
            return safeHglobalHandle;
        }

        public static SafeHGlobalHandle AllocHGlobal(string s) => new SafeHGlobalHandle(Marshal.StringToHGlobalUni(s));

        public IntPtr ToIntPtr() => pointer;

        public void Dispose()
        {
            if (pointer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pointer);
                pointer = IntPtr.Zero;
            }
            GC.SuppressFinalize((object)this);
        }

        private static SafeHGlobalHandle AllocHGlobal(int cb)
        {
            if (cb < 0)
                throw new ArgumentOutOfRangeException(nameof(cb), "The value of this argument must be non-negative");
            SafeHGlobalHandle safeHglobalHandle = new SafeHGlobalHandle();
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
            }
            finally
            {
                safeHglobalHandle.pointer = Marshal.AllocHGlobal(cb);
            }
            return safeHglobalHandle;
        }
    }
    internal static class IntPtrExtensions
    {
        public static IntPtr Increment(this IntPtr ptr, int cbSize) => new IntPtr(ptr.ToInt64() + (long)cbSize);

        public static IntPtr Increment<T>(this IntPtr ptr) => ptr.Increment(Marshal.SizeOf(typeof(T)));

        public static T ElementAt<T>(this IntPtr ptr, int index)
        {
            int cbSize = Marshal.SizeOf(typeof(T)) * index;
            return (T)Marshal.PtrToStructure(ptr.Increment(cbSize), typeof(T));
        }
    }
}
*/