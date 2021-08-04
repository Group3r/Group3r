using System;
using System.Collections.Generic;

namespace LibSnaffle.ActiveDirectory
{
    public class PackageSetting : GpoSetting
    {
        public string DisplayName { get; set; }
        public string DistinguishedName { get; set; }
        public List<string> MsiFileList { get; set; } = new List<string>();
        public DateTime CreatedDate { get; set; }
        public DateTime ModifiedDate { get; set; }
        public string AdsPath { get; set; }
        public Guid ProductCode { get; set; }
        public string Cn { get; set; }
        public Guid UpgradeProductCode { get; set; }
        public string MsiScriptName { get; set; }
        public string PackageAction { get; set; }
        public string ParentGpo { get; set; }
    }
}