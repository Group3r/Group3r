using System.Collections.Generic;
using System.Security.AccessControl;
using LibSnaffle.ActiveDirectory;
using LibSnaffle.Classifiers.Results;
using LibSnaffle.Classifiers.Rules;
using Group3r.Assessment;

namespace Group3r.Assessment
{
    public class GpoFinding
    {
        public string FindingReason { get; set; }
        public string FindingDetail { get; set; }
        public Constants.Triage Triage { get; set; }
        public List<PathFinding> PathFindings { get; set; }
        public List<SimpleAce> AclResult { get; set; }
        public GpoSetting GpoSetting { get; set; }
    }

    public abstract class PathFinding
    {
        // path-finding-specific fields
        public string AssessedPath { get; set; }
        public bool FileExists { get; set; }
        public bool FileWritable { get; set; }
        public bool DirectoryExists { get; set; }
        public bool DirectoryWritable { get; set; }
        public string ParentDirectoryExists { get; set; }
        public bool ParentDirectoryWritable { get; set; }
        public FileSecurity FileSecurity { get; set; }
        public Sddl.Parser.Sddl FileSecuritySddl { get; set; }
        public DirectorySecurity DirectorySecurity { get; set; }
        public Sddl.Parser.Sddl DirSecuritySddl { get; set; }
        public List<SimpleAce> AclResult { get; set; }
        public DirResult DirResult { get; set; }
        public FileResult FileResult { get; set; }

        public abstract void SetProperties(string originalPath, SddlAnalyser sddlAnalyser);
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
        public AccessType AccessType {get; set;}
        /*
         trustee with access
        reason it's interesting

         */
    }
}