using LibSnaffle.Concurrency;
using LibSnaffle.Errors;
using System;
using System.Collections.Generic;
using System.IO;

namespace LibSnaffle.ActiveDirectory
{
    /**
     * Summary: Helper fo loading a sysvol. Does error handling etc.
     *          Connecting to and reading a Sysvol from file or network.
     *          Throws a SysVolException if it fails to load. This should be handled by the caller.
     *          Currently requires a BlockingMq for logging.
     *          TODO: decouple from Mq?
     */
    public class SysvolHelper
    {
        public BlockingMq Logger { get; set; }

        public SysvolHelper(BlockingMq mq)
        {
            Logger = mq;
        }
    
        /**
         * Summary: Loads the sysvol from disk.
         * Imports: string sysvolPath, BlockingMq mq
         * Exports: Sysvol
         */
        public Sysvol LoadSysvolOffline(string sysvolPath)
        {
            ValidateSysvolPath(sysvolPath);
            return new Sysvol(sysvolPath, Logger);
        }

        /**
          * Summary: Loads the sysvol over the network.
          * Imports: string targetDomain, BlockingMq mq
          * Exports: Sysvol
          */
        public Sysvol LoadSysvolOnlineByDomain(string targetDomain)
        {
            string sysvolPath;

            sysvolPath = @"\\" + targetDomain + @"\sysvol\" + targetDomain + @"\";
            ValidateSysvolPath(sysvolPath);

            return new Sysvol(sysvolPath, Logger);
        }

        /**
         * Summary: Loads the sysvol over the network.
         * Imports: string targetDomain, string targetDc, BlockingMq mq
         * Exports: Sysvol
         */
        public Sysvol LoadSysvolOnlineByDc(string targetDomain, string targetDc)
        {
            string sysvolPath;

            sysvolPath = @"\\" + targetDc + @"\sysvol\" + targetDomain + @"\";
            ValidateSysvolPath(sysvolPath);

            return new Sysvol(sysvolPath, Logger);
        }

        /**
         * Summary: Loads sysvol given a path. Throws a SysVolException if it failes to load.
         * Arguments: Path to sysvol, can be a file or UNC path
         * Returns: Nothing, but exports Dirs and Files
         * TODO: Check for other exceptions to catch when trying to load (esp online).
         */
        private bool ValidateSysvolPath(string sysvolPath)
        {
            if (String.IsNullOrEmpty(sysvolPath))
            {
                throw new SysvolException("Failed to load SysVol, empty path.");
            }
            try
            {
                // TODO: does Exists() do what we need it to to validate the path is legit?
                Directory.Exists(sysvolPath);
            }
            catch (DirectoryNotFoundException e)
            {
                throw new SysvolException("Failed to read SYSVOL from " + sysvolPath, e);
            }

            return true;
        }
    }
}
