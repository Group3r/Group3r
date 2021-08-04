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
        public bool CanRead { get; set; }
        public bool CanWrite { get; set; }

        public DirResult(DirectoryInfo dirInfo)
        {
            ResultDirInfo = dirInfo;
            CanRead = CanIRead();
            CanWrite = CanIWrite();
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
                    if (currentUserSecurity.HasAccess(ResultDirInfo, fsRight)) readRight = true;
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
                FileSystemRights.WriteData,
                FileSystemRights.CreateDirectories,
                FileSystemRights.CreateFiles,
                FileSystemRights.Delete,
                FileSystemRights.DeleteSubdirectoriesAndFiles
            };

            bool writeRight = false;
            foreach (FileSystemRights fsRight in fsRights)
                try
                {
                    if (currentUserSecurity.HasAccess(ResultDirInfo, fsRight)) writeRight = true;
                }
                catch (UnauthorizedAccessException)
                {
                    return false;
                }

            return writeRight;
        }
    }
}
