using System.Collections.Generic;
using System.Text.RegularExpressions;
using LibSnaffle.ActiveDirectory;
using LibSnaffle.Classifiers;
using LibSnaffle.Classifiers.Rules;

namespace Group3r.Options.AssessmentOptions
{
    public partial class AssessmentOptions
    {
        public List<PrivRightOption> PrivRights { get; set; }
        public List<TrusteeOption> TrusteeOptions { get; set; }
        public List<RegKey> RegKeys { get; set; }
        public List<string> ExeAndScriptExtentions { get; set; }
        public List<string> ConfigFileExtensions { get; set; }
        public List<string> OfficeMacroExtensions { get; set; }
        public ClassifierOptions ClassifierOptions { get; set; }
        public List<string> TargetTrustees { get; set; }
        public Constants.Triage MinTriage { get; set; } = Constants.Triage.Green;
        public List<string> InterestingRights { get; set; } = new List<string>()
        {
            "Owner",
            "CREATE_CHILD",
            "GENERIC_WRITE",
            "WRITE_ATTRIBUTES",
            "WRITE_PROPERTIES",
            "WRITE_PROPERTY",
            "APPEND_DATA",
            "WRITE_DATA",
            "ALL_ACCESS",
            "DELETE_CHILD",
            "STANDARD_DELETE",
            "DELETE_TREE",
            "ADD_FILE",
            "ADD_SUBDIRECTORY",
            "CREATE_PIPE_INSTANCE",
            "WRITE",
            "CREATE_LINK",
            "SET_VALUE",
            "WRITE_DAC",
            "WRITE_OWNER"
        };

        public AssessmentOptions()
        {
            // create default snaffler rules
            ClassifierOptions = new ClassifierOptions();
            ClassifierOptions.AllRules = new ClassifierRules();
            ClassifierOptions.AllRules.BuildDefaultClassifiers();
            ClassifierOptions.AllRules.PrepareClassifiers();

            LoadPrivRights();
            LoadTrusteeOptions();
            LoadRegKeys();
            LoadExeAndScriptExtensions();
            LoadConfigFileExtensions();
            LoadOfficeMacroExtensions();
        }
    }

    public class PrivRightOption
    {
        public string PrivRightName { get; set; }
        public bool GrantsRemoteAccess { get; set; }
        public string RemoteAccessDesc { get; set; }
        public bool LocalPrivesc { get; set; }
        public string LocalPrivescDesc { get; set; }
        public string MsDescription { get; set; }
    }

    public class TrusteeOption
    {
        public string SID { get; set; }
        public string DisplayName { get; set; }
        public string Description { get; set; }
        public bool DomainSID { get; set; } // is this the sid of a domain group/account?
        public bool LocalSID { get; set; } // is this the sid of a local group/account?
        public bool HighPriv { get; set; } // is this group/account canonically high-priv, i.e. do they have well-known paths to get local Admin/Domain Admin by default?
        public bool LowPriv { get; set; } // is this group/account canonically low-priv, i.e. are they one of the massive default groups like Domain Users etc.
    }

    public enum InterestingIf
    {
        Present,
        Bad,
        NotGood,
        NotDefault
    }

    public class RegKey
    {
        public string MsDesc { get; set; }
        public string FriendlyDescription { get; set; }
        public RegHive RegHive { get; set; }
        public string Key { get; set; }
        public string ValueName { get; set; }
        public RegKeyValType ValueType { get; set; }
        public InterestingIf InterestingIf { get; set; }
        public byte[] DefaultBinary { get; set; }
        public int DefaultDword { get; set; }
        public string DefaultSz { get; set; }
        public byte[] GoodBinary { get; set; }
        public string GoodSz { get; set; }
        public int GoodDword { get; set; }
        public byte[] BadBinary { get; set; }
        public string BadSz { get; set; }
        public int BadDword { get; set; }
        public Constants.Triage Triage { get; set; }
    }
}

/*
"interestingWords": [
"nattend.xml",
"passw",
"kdb",
"putty.config",
"winscp.ini",
"id_rsa",
"id_dsa",
"web.config",
"ppk",
"ssh",
"rdp",
"cred",
"-p ",
"/u ",
"psexec",
"net user",
"key",
"vnc",
"vpn",
"powershell",
"cmd",
"/c ",
"path",
"-command"
]
}
 */