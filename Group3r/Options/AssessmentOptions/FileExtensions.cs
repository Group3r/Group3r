using System.Collections.Generic;

namespace Group3r.Options.AssessmentOptions
{
    public partial class AssessmentOptions
    {

        public void LoadExeAndScriptExtensions()
        {
            ExeAndScriptExtentions = new List<string>()
            {
                "exe",
                "msi",
                "bat",
                "cmd",
                "hta",
                "ps1",
                "vbs",
                "scr",
                "com",
                "psd1",
                "psm1",
                "lnk"
            }; // yeah i know it's not technically but it works like these so it's going here.
        }

        public void LoadConfigFileExtensions()
        {
            ConfigFileExtensions = new List<string>()
            {
                "config",
                "xml",
                "json",
                "ini",
                "rdp",
                "conf",
                "cnf"
            };
        }

        public void LoadOfficeMacroExtensions()
        {
            OfficeMacroExtensions = new List<string>()
            {
                "dot",
                "dotm",
                "doc",
                "docm",
                "xlt",
                "xls",
                "xltm",
                "xlsm",
                "pot",
                "potm",
                "ppt",
                "pptm"
            };
        }
    }
}