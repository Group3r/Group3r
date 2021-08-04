using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace LibSnaffle.ActiveDirectory
{
    public class IniFileSetting : GpoSetting
    {
        public string Name { get; set; }
        public string Path { get; set; }
        public SettingAction Action { get; set; }
        public string IniFileAction { get; set; }
        public string Section { get; set; }
        public string Value { get; set; }
        public string Property { get; set; }
    }
}
