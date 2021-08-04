using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace LibSnaffle.ActiveDirectory
{
    public class SystemAccessSetting : GpoSetting
    {
        public string SettingName { get; set; } = "";
        public string ValueString { get; set; } = "";

    }
}
