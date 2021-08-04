using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace LibSnaffle.ActiveDirectory
{
    public class PrinterSetting : GpoSetting
    {
        public string Name { get; set; }
        public SettingAction Action { get; set; }
        public string PrinterAction { get; set; }
        public string Path { get; set; }
        public string Comment { get; set; }
        public string UserName { get; set; }
        public string Cpassword { get; set; }
        public string Password { get; set; }
        public string Port { get; set; }
    }
}
