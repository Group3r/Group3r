using System;
using System.Collections.Generic;

namespace LibSnaffle.ActiveDirectory
{
    /// <summary>
    /// Represents a Group Policy Object.
    /// </summary>
    public class GPO
    {
        public GPOAttributes Attributes { get; set; } = new GPOAttributes();
        public List<string> GpoFiles { get; set; } = new List<string>();
        public List<GpoSetting> Settings { get; set; } = new List<GpoSetting>();


        public GPO()
        {
            // parameterless constructor to allow subclass
        }

        public GPO(string uid)
        {
            Attributes.Uid = uid;
        }

        public GPO(string uid, string pathInSysvol, bool morphed)
        {
            Attributes.Uid = uid;
            Attributes.PathInSysvol = pathInSysvol;
            Attributes.IsMorphedGPO = morphed;
        }
    }

    public class GPOLink
    {
        public string LinkPath { get; set; }
        public string LinkEnforced { get; set; }
    }

    public class GPOAttributes
    {
        public bool IsMorphedGPO { get; set; } = false;
        public List<GPOLink> GpoLinks { get; set; } = new List<GPOLink>();
        public string AdsPath { get; set; }
        public string DisplayName { get; set; }
        public DateTime CreatedDate { get; set; }
        public DateTime ModifiedDate { get; set; }
        //        public byte[] NtSecurityDescriptor { get; set; }
        public string NtSecurityDescriptor { get; set; }
        public Sddl.Parser.Sddl NtSecurityDescriptorSddl { get; set; }
        public string DistinguishedName { get; set; }
        public string PathInSysvol { get; set; }
        //public string Cn { get; set; }
        public string Uid { get; set; }
        public string VersionNumber { get; set; }
        public bool ComputerPolicyEnabled { get; set; }
        public bool UserPolicyEnabled { get; set; }
    }
}
