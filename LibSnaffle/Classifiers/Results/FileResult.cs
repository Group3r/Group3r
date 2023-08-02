using System.IO;
using static LibSnaffle.Classifiers.Rules.Constants;

namespace LibSnaffle.Classifiers.Results
{
    public class FileResult : Result
    {
        public FileInfo ResultFileInfo { get; set; }
        public TextResult TextResult { get; set; }

        public Triage Triage { get; set; }

        public FileResult(FileInfo fileInfo, bool snaffle, long maxSizeToSnaffle, string snafflePath)
        {
            ResultFileInfo = fileInfo;
        }

        public void CopyFile(FileInfo fileInfo, string snafflePath)
        {
            string sourcePath = fileInfo.FullName;
            // clean it up and normalise it a bit
            string cleanedPath = sourcePath.Replace(':', '.').Replace('$', '.').Replace("\\\\", "\\");
            //string cleanedPath = Path.GetFullPath(sourcePath.Replace(':', '.').Replace('$', '.'));
            // make the dir exist
            string snaffleFilePath = Path.Combine(snafflePath, cleanedPath);
            string snaffleDirPath = Path.GetDirectoryName(snaffleFilePath);
            Directory.CreateDirectory(snaffleDirPath);
            File.Copy(sourcePath, (Path.Combine(snafflePath, cleanedPath)), true);
        }


    }
}
