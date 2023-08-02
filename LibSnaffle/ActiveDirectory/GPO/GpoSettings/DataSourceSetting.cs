using System.Collections.Generic;

namespace LibSnaffle.ActiveDirectory
{
    public class DataSourceSetting : GpoSetting
    {
        public string Name { get; set; } = "";
        public SettingAction Action { get; set; }
        public string UserName { get; set; } = "";
        public string Cpassword { get; set; } = "";
        public string Password { get; set; } = "";
        public string DSN { get; set; } = "";
        public string Driver { get; set; } = "";
        public string Description { get; set; } = "";
        public Dictionary<string, string> Attributes { get; set; }
    }
}
