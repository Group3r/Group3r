using Group3r.Options.AssessmentOptions;
using LibSnaffle.Classifiers.Results;
using Sddl.Parser;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;

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
        public AssessmentOptions AssessmentOptions { get; set; }
        public SddlAnalyser SddlAnalyser { get; set; }

        //public string[] ReadRights { get; set; } = new string[] { "Read", "ReadAndExecute", "ReadData", "ListDirectory" };
        public string[] WriteRights { get; set; } = new string[] { "CREATE_LINK", "WRITE", "WRITE_OWNER", "WRITE_DAC", "APPEND_DATA", "WRITE_DATA", "CREATE_CHILD", "FILE_WRITE", "ADD_FILE", "ADD_SUBDIRECTORY", "Owner" };
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

            if (suckItAndSee)
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
                                if (WriteRights.Contains(right))
                                {
                                    grantsWrite = true;
                                }
                                if (ModifyRights.Contains(right)) { grantsModify = true; }
                            }

                            // check if it's allow or deny
                            if (simpleAce.ACEType == ACEType.Deny) { denyRight = true; }

                            if (denyRight) { continue; } // TODO actually handle deny rights properly

                            TrusteeOption match = new TrusteeOption();
                            //see if the trustee is a users/group we know about.
                            if (simpleAce.Trustee.DisplayName != null)
                            {
                                IEnumerable<TrusteeOption> nameMatches = AssessmentOptions.TrusteeOptions.Where(trusteeopt => trusteeopt.DisplayName == simpleAce.Trustee.DisplayName);
                                if (nameMatches.Any()) { match = nameMatches.First(); }
                            }
                            if (simpleAce.Trustee.Sid != null)
                            {
                                IEnumerable<TrusteeOption> sidMatches =
                                    AssessmentOptions.TrusteeOptions.Where(trusteeopt =>
                                        trusteeopt.SID == simpleAce.Trustee.Sid);
                                if (sidMatches.Any()) { match = sidMatches.First(); }
                            }

                            if (match.DisplayName != null)
                            {
                                // check if it's one of the aggravating principals that are both local and domain and windows struggles to distinguish between:
                                if (match.DisplayName == "Administrators" ||
                                    match.DisplayName == "Administrator" ||
                                    match.DisplayName == "SYSTEM" ||
                                    match.DisplayName == "Local System")
                                {
                                    continue;
                                }
                                // so if it's a user/group that we know about...
                                if (match.Target || match.LowPriv)
                                {
                                    // and it's either canonically low-priv or we are a member of it
                                    //set rwStatus based on it.
                                    if (grantsModify)
                                    {
                                        rwStatus.CanModify = true;
                                    }

                                    if (grantsWrite)
                                    {
                                        rwStatus.CanWrite = true;
                                    }
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
