using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.AccessControl;
using System.Text;

namespace LibSnaffle.ActiveDirectory
{
    public class NtServiceSetting : GpoSetting
    {
        public string Name { get; set; }
        public string Sddl { get; set; }
        public Sddl.Parser.Sddl ParsedSddl { get; set; }
        public string ServiceName { get; set; }
        public string Timeout { get; set; }
        public string StartupType { get; set; }
        public string UserName { get; set; }
        public string Cpassword { get; set; }
        public string Password { get; set; }
        public string ServiceAction { get; set; }
        public string Program { get; set; }
        public string Args { get; set; }
        public string ActionOnFirstFailure { get; set; }
        //TODO possible there are second and third failures, check.
        public string Append { get; set; }
        public string AccountName { get; set; }
        public string ResetFailCountDelay { get; set; }
        public string Interact { get; set; }
    }
}
