using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace LibSnaffle.ActiveDirectory
{
    public class KerbPolicySetting : GpoSetting
    {
        public string Key { get; set; } = "";
        public string Value { get; set; } = "";
    }
}
