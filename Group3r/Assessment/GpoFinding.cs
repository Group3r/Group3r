using LibSnaffle.Classifiers.Results;
using LibSnaffle.Classifiers.Rules;
using System.Collections.Generic;
using System.IO;

namespace BigFish.Assessment
{
    public class GpoFinding
    {
        public string FindingReason { get; set; }
        public string FindingDetail { get; set; }
        public Constants.Triage Triage { get; set; }
        public List<PathResult> PathFindings { get; set; } = new List<PathResult>();
        public List<SimpleAce> AclResult { get; set; } = new List<SimpleAce>();
    }

    public abstract class PathResult
    {
        // path-finding-specific fields
        public string AssessedPath { get; set; }
        public bool FileExists { get; set; }
        public bool FileWritable { get; set; }
        public bool DirectoryExists { get; set; }
        public bool DirectoryWritable { get; set; }
        public string ParentDirectoryExists { get; set; }
        public bool ParentDirectoryWritable { get; set; }
        public List<DirResult> SnaffDirResults { get; set; } = new List<DirResult>();
        public List<FileResult> SnaffFileResults { get; set; } = new List<FileResult>();
        public RwStatus RwStatus { get; set; }
        public abstract void SetProperties(string originalPath, bool exists);
    }

    //Just putting these here for now until I can think of or realise a better place to store them.
    public class FilePathResult : PathResult
    {
        public override void SetProperties(string originalPath, bool exists)
        {
            if (exists)
            {
                FileInfo fileInfo = new FileInfo(originalPath);
                //FileSecurity = fileInfo.GetAccessControl(System.Security.AccessControl.AccessControlSections.Access | System.Security.AccessControl.AccessControlSections.Owner);
                //string fileSecuritySddlString = FileSecurity.GetSecurityDescriptorSddlForm(System.Security.AccessControl.AccessControlSections.Access | System.Security.AccessControl.AccessControlSections.Owner);
                //AclResult = sddlAnalyser.AnalyseSddl(new Sddl.Parser.Sddl(fileSecuritySddlString, Sddl.Parser.SecurableObjectType.File));
                FileExists = true;
            }
            AssessedPath = originalPath;
        }
    }

    public class DirPathResult : PathResult
    {
        public override void SetProperties(string originalPath, bool exists)
        {
            if (exists)
            {
                DirectoryInfo dirInfo = new DirectoryInfo(originalPath);
                //DirectorySecurity = dirInfo.GetAccessControl(System.Security.AccessControl.AccessControlSections.Access | System.Security.AccessControl.AccessControlSections.Owner);
                //string dirSecuritySddlString = DirectorySecurity.GetSecurityDescriptorSddlForm(System.Security.AccessControl.AccessControlSections.Access | System.Security.AccessControl.AccessControlSections.Owner);
                //AclResult = sddlAnalyser.AnalyseSddl(new Sddl.Parser.Sddl(dirSecuritySddlString, Sddl.Parser.SecurableObjectType.Directory));
                DirectoryExists = true;
            }
            AssessedPath = originalPath;
        }
    }

    public enum AccessType
    {
        READ,
        WRITE,
        MODIFY,
        FULL
    }

    public class SddlFinding
    {
        public string FindingReason { get; set; }
        public string FindingDetail { get; set; }
        public AccessType AccessType { get; set; }
        /*
         trustee with access
        reason it's interesting

         */
    }
}