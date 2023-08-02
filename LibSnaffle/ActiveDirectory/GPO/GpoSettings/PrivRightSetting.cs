using System.Collections.Generic;

namespace LibSnaffle.ActiveDirectory
{
    public class PrivRightSetting : GpoSetting
    {
        public string Privilege { get; set; }
        public List<string> TrusteeSids { get; set; } = new List<string>();
        public List<Trustee> Trustees { get; set; } = new List<Trustee>();
        public string Description { get; set; }
    }
}
