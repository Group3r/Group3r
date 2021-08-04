using System;
using System.Collections.Generic;
using Sddl.Parser;

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
            this.Attributes.Uid = uid;
        }

        public GPO(string uid, string pathInSysvol)
        {
            this.Attributes.Uid = uid;
            this.Attributes.PathInSysvol = pathInSysvol;
        }
    }

    public class GPOAttributes
    {
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
        public bool Enabled { get; set; }
        public List<string> GPOLinks { get; set; }
    }
}
