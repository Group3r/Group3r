using LibSnaffle.FileDiscovery;
using System;
using System.IO;
using System.Security.AccessControl;
using static LibSnaffle.Classifiers.Rules.Constants;

namespace LibSnaffle.Classifiers.Results
{
    public class DirResult : Result
    {
        public bool ScanDir { get; set; }
        public string DirPath { get; set; }
        public DirectoryInfo ResultDirInfo { get; set; }
        public Triage Triage { get; set; }

        public DirResult(DirectoryInfo dirInfo)
        {
            ResultDirInfo = dirInfo;
            this.RwStatus = EffectiveAccess.EffectivePermissions.CanRw(dirInfo);
        }


    }
}
