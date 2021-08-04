using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace LibSnaffle.ActiveDirectory
{
    public class UserSetting : GpoSetting
    {
        public string Name { get; set; }
        public string NewName { get; set; }
        public string FullName { get; set; }
        public string UserName { get; set; }
        public string Cpassword { get; set; }
        public string Password { get; set; }
        public bool AccountDisabled { get; set; }
        public bool PwNeverExpires { get; set; }
        public SettingAction Action { get; set; }
        public string UserAction { get; set; }
        public string Description { get; set; }
    }
}
