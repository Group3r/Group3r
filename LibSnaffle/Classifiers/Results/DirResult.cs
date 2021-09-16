using System.IO;
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
            RwStatus = EffectiveAccess.EffectivePermissions.CanRw(dirInfo);
        }


    }
}
