using LibSnaffle.Concurrency;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace LibSnaffle.FileDiscovery
{
    /// <summary>
    /// Represents a filesystem (disk or share)
    /// </summary>
    public class FileSystem
    {
        /// <summary>
        /// HostShareInfo
        /// </summary>
        public HostShareInfo Info { get; set; }

        /// <summary>
        /// Path to the filesystem.
        /// </summary>
        public string Path { get; set; }

        public FileSystem(HostShareInfo info, string path)
        {
            Info = info;
            Path = path;
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct HostShareInfo
    {
        public string shi1_netname;
        public uint shi1_type;
        public string shi1_remark;

        public HostShareInfo(string sharename, uint sharetype, string remark)
        {
            shi1_netname = sharename;
            shi1_type = sharetype;
            shi1_remark = remark;
        }

        public override string ToString()
        {
            return shi1_netname;
        }
    }

    /// <summary>
    /// Provides funcionality to find filesystems and enumerate files.
    /// </summary>
    public class FileSystemEnumerator
    {
        public FileSystemEnumerator()
        {
        }

        /// <summary>
        /// Walks all subdirectories and return an IEnumerable containing the path to every file that was dicovered.
        /// </summary>
        /// <param name="rootPath">
        /// Path to start the search at.
        /// </param>
        /// <returns>
        /// Return a list of all files in a directory.
        /// </returns>
        public IEnumerable<string> ListAllFiles(string rootPath)
        {
            var foundFiles = Enumerable.Empty<string>();

            try
            {
                IEnumerable<string> subDirs = Directory.EnumerateDirectories(rootPath);
                foreach (string dir in subDirs)
                {
                    foundFiles = foundFiles.Concat(ListAllFiles(dir));
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (PathTooLongException) { }
            catch (IOException) { }

            try
            {
                foundFiles = foundFiles.Concat(Directory.EnumerateFiles(rootPath));
            }
            catch (UnauthorizedAccessException) { }
            catch (PathTooLongException) { }
            catch (IOException) { }

            return foundFiles;
        }

        /// <summary>
        /// Recursively walks a filesystem and when a file is found, immediatly shecules an Action.
        /// </summary>
        /// <param name="walkSchedule">
        /// BlockingStaticTaskScheduler to add Actions to.
        /// </param>
        /// <param name="rootPath">
        /// Path to begin the walk.
        /// </param>
        /// <param name="q">
        /// The Queue so that it's available in the action.
        /// </param>
        /// <param name="action">
        /// The Action delegate to be scheduled for each file.
        /// </param>
        public void WalkScheduler(BlockingStaticTaskScheduler walkSchedule, string rootPath, BlockingMq q, Action<Object> action)
        {
            FileAttributes attr = File.GetAttributes(rootPath);
            if (attr.HasFlag(FileAttributes.Directory)) // It's a directory.
            {
                try
                {
                    //Schedule a task for each file in the dir.
                    foreach (string file in Directory.EnumerateFiles(rootPath))
                    {
                        QueueAndPath qp = new QueueAndPath(q, file);
                        walkSchedule.New(action, qp);
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (PathTooLongException) { }
                catch (IOException) { }

                try
                {
                    // Recurse on each subdir.
                    IEnumerable<string> subDirs = Directory.EnumerateDirectories(rootPath);
                    foreach (string dir in subDirs)
                    {
                        WalkScheduler(walkSchedule, dir, q, action);
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (PathTooLongException) { }
                catch (IOException) { }
            }
            else // It's a file, just queue a task.
            {
                QueueAndPath qp = new QueueAndPath(q, rootPath);
                walkSchedule.New(action, qp);
            }
        }


        /// <summary>
        /// Used to check if a filesystem is readable.
        /// </summary>
        /// <param name="share">
        /// Path to the share
        /// </param>
        /// <returns>
        /// True if readable.
        /// </returns>
        public bool IsShareReadable(string share)
        {
            try
            {
                string[] files = Directory.GetFiles(share);
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
            catch (DirectoryNotFoundException)
            {
                return false;
            }
            catch (IOException)
            {
                return false;
            }
            catch (Exception e)
            {
                //Mq.Trace(e.ToString());
            }
            return false;
        }

        /// <summary>
        /// Used to enumerate all mounted drives on a remote windows machine.
        /// </summary>
        /// <param name="computer">
        /// IP or hostname of machine.
        /// </param>
        /// <returns>
        /// List of FileSystem objects reflecting all mounted drives.
        /// </returns>
        public List<FileSystem> EnumerateMountedDrives(string computer)
        {
            // find the shares
            List<FileSystem> shares = new List<FileSystem>();

            foreach (HostShareInfo hostShareInfo in GetHostShareInfo(computer))
            {
                shares.Add(new FileSystem(hostShareInfo, GetShareName(hostShareInfo, computer)));
            }

            return shares;
        }

        /// <summary>
        /// Gets the fill name of a share.
        /// </summary>
        /// <param name="hostShareInfo"></param>
        /// <param name="computer">IP or hostname of target.</param>
        /// <returns></returns>
        private string GetShareName(HostShareInfo hostShareInfo, string computer)
        {
            // takes a HostShareInfo object and a computer name and turns it into a usable path.

            // first we want to throw away any errored out ones.
            string[] errors = { "ERROR=53", "ERROR=5" };
            if (errors.Contains(hostShareInfo.shi1_netname))
            {
                //Mq.Trace(hostShareInfo.shi1_netname + " on " + computer +
                //", but this is usually no cause for alarm.");
                return null;
            }
            return $"\\\\{computer}\\{hostShareInfo.shi1_netname}";
        }

        /// <summary>
        /// Gets HostShareInfo for all shares on a host.
        /// </summary>
        /// <param name="computer">
        /// The target machine.
        /// </param>
        /// <returns></returns>
        private List<HostShareInfo> GetHostShareInfo(string computer)
        {
            // gets a share info object when given a host.
            List<HostShareInfo> shareInfos = new List<HostShareInfo>();
            int entriesread = 0;
            int totalentries = 0;
            int resumeHandle = 0;
            int nStructSize = Marshal.SizeOf(typeof(HostShareInfo));
            IntPtr bufPtr = IntPtr.Zero;
            int ret = NetShareEnum(new StringBuilder(computer), 1, ref bufPtr, MaxPreferredLength, ref entriesread,
                ref totalentries,
                ref resumeHandle);
            if (ret == NerrSuccess)
            {
                IntPtr currentPtr = bufPtr;
                for (int i = 0; i < entriesread; i++)
                {
                    HostShareInfo shi1 = (HostShareInfo)Marshal.PtrToStructure(currentPtr, typeof(HostShareInfo));
                    shareInfos.Add(shi1);
                    currentPtr += nStructSize;
                }

                NetApiBufferFree(bufPtr);
                return shareInfos;
            }

            shareInfos.Add(new HostShareInfo("ERROR=" + ret, 10, string.Empty));
            return shareInfos;
        }

        // HERE BE WIN32 DRAGONS
        // ---------------------

        [DllImport("Netapi32.dll", SetLastError = true)]
        private static extern int NetWkstaGetInfo(string servername, int level, out IntPtr bufptr);

        [DllImport("Netapi32.dll", SetLastError = true)]
        private static extern int NetApiBufferFree(IntPtr buffer);

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetShareEnum(
            StringBuilder serverName,
            int level,
            ref IntPtr bufPtr,
            uint prefmaxlen,
            ref int entriesread,
            ref int totalentries,
            ref int resumeHandle
        );

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WkstaInfo100
        {
            public int platform_id;
            public string computer_name;
            public string lan_group;
            public int ver_major;
            public int ver_minor;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct ShareInfo0
        {
            public string shi0_netname;
        }

        private const uint MaxPreferredLength = 0xFFFFFFFF;
        private const int NerrSuccess = 0;

        private enum NetError : uint
        {
            NerrSuccess = 0,
            NerrBase = 2100,
            NerrUnknownDevDir = (NerrBase + 16),
            NerrDuplicateShare = (NerrBase + 18),
            NerrBufTooSmall = (NerrBase + 23)
        }

        private enum ShareType : uint
        {
            StypeDisktree = 0,
            StypePrintq = 1,
            StypeDevice = 2,
            StypeIpc = 3,
            StypeSpecial = 0x80000000
        }
    }
}