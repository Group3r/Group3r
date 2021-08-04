using LibSnaffle.FileDiscovery;
using System;
using System.IO;
using System.Security.AccessControl;
using static LibSnaffle.Classifiers.Rules.Constants;

namespace LibSnaffle.Classifiers.Results
{
    public class FileResult : Result
    {
        public FileInfo ResultFileInfo { get; set; }
        public TextResult TextResult { get; set; }
        public bool CanRead { get; set; }
        public bool CanWrite { get; set; }
        public Triage Triage { get; set; }

        public FileResult(FileInfo fileInfo, bool snaffle, long maxSizeToSnaffle, string snafflePath)
        {
            ResultFileInfo = fileInfo;
            CanRead = CanIRead();
            CanWrite = CanIWrite();
            
            if (snaffle)
            {
                if ((maxSizeToSnaffle >= fileInfo.Length) && CanRead)
                {
                    CopyFile(fileInfo, snafflePath);
                }
            }
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

        public bool CanIRead()
        {
            // this will return true if file read perm is available.
            CurrentUserSecurity currentUserSecurity = new CurrentUserSecurity();

            FileSystemRights[] fsRights =
            {
                FileSystemRights.Read,
                FileSystemRights.ReadAndExecute,
                FileSystemRights.ReadData
            };

            bool readRight = false;
            foreach (FileSystemRights fsRight in fsRights)
                try
                {
                    if (currentUserSecurity.HasAccess(ResultFileInfo, fsRight)) readRight = true;
                }
                catch (UnauthorizedAccessException)
                {
                    return false;
                }

            return readRight;
        }

        public bool CanIWrite()
        {
            // this will return true if write or modify or take ownership or any of those other good perms are available.
            CurrentUserSecurity currentUserSecurity = new CurrentUserSecurity();

            FileSystemRights[] fsRights =
            {
                FileSystemRights.Write,
                FileSystemRights.Modify,
                FileSystemRights.FullControl,
                FileSystemRights.TakeOwnership,
                FileSystemRights.ChangePermissions,
                FileSystemRights.AppendData,
                FileSystemRights.WriteData
            };

            bool writeRight = false;
            foreach (FileSystemRights fsRight in fsRights)
                try
                {
                    if (currentUserSecurity.HasAccess(ResultFileInfo, fsRight)) writeRight = true;
                }
                catch (UnauthorizedAccessException)
                {
                    return false;
                }

            return writeRight;
        }
    }
}
