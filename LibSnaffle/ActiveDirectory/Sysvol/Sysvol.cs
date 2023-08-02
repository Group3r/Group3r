using LibSnaffle.Concurrency;
using LibSnaffle.Errors;
using LibSnaffle.FileDiscovery;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace LibSnaffle.ActiveDirectory
{
    ///<summary>
    ///Represents a SYSVOL directory.
    ///</summary>
    ///<remarks>
    ///Stores the path to SYSVOL, and a list of GPO directories and GPO objects therein.
    ///</remarks>
    public class Sysvol
    {
        public List<string> GpoDirs { get; private set; }
        public List<GPO> Gpos { get; set; }
        public string SysvolPath { get; private set; }
        private BlockingMq Logger;

        public Sysvol(List<string> gpoDirs, List<GPO> gpos, string sysvolPath)
        {
            GpoDirs = gpoDirs;
            SysvolPath = sysvolPath;
            Gpos = gpos;
        }

        /// <summary>
        /// Alternate constructor to enum and populate the GPOs given a list of GPO directories.
        /// </summary>
        /// <param name="gpoDirs">
        /// List of GPO directories.
        /// </param>
        public Sysvol(List<string> gpoDirs)
        {
            GpoDirs = gpoDirs;
            SysvolPath = "";
            Gpos = EnumerateSysvolGpos(GpoDirs);
        }

        /// <summary>
        /// Alternate constructor to enum and populate the sysvol given a path.
        /// </summary>
        /// <param name="sysvolPath"></param>
        /// <param name="logger"></param>
        public Sysvol(string sysvolPath, BlockingMq logger)
        {
            Logger = logger;
            SysvolPath = sysvolPath;
            Logger.Trace("Enumerating GPO directories.");
            GpoDirs = EnumerateGPODirectories(sysvolPath);
            Logger.Trace("Enumerating SYSVOL GPOs.");
            Gpos = EnumerateSysvolGpos(GpoDirs);
        }

        /// <summary>
        /// Walks sysvol and adds GPOs that it finds.
        /// </summary>
        /// <remarks>
        /// Assumes that a file/directory in ./policies that is a guid is a GP directory.
        /// </remarks>
        /// <param name="sysvolPath">
        /// Path to SYSVOL.
        /// </param>
        /// <returns>
        /// List of all GPO filepaths.
        /// </returns>
        private List<string> EnumerateGPODirectories(string sysvolPath)
        {
            List<string> gpoDirs = new List<string>();
            List<string> dirs = new List<string>();
            try
            {
                dirs = Directory.GetDirectories(sysvolPath).ToList<string>();
            }
            catch (Exception e)
            {
                if (Logger != null)
                {
                    Logger.Error(e.Message);
                    Logger.Error("Failed to list the contents of SYSVOL - make sure you can access SYSVOL as the current user.");
                    Logger.Terminate();
                }
            }
            foreach (string dir in dirs)
            {
                Logger.Trace("Looking for policies dirs in " + dir);

                if (dir.ToLower().Contains("policies"))
                {
                    if (dir.ToLower().Contains("ntfrs"))
                    {
                        Logger.Trace("Found a morphed policies directory: " + dir);
                    }
                    Logger.Trace("Found policies dir in " + dir);
                    try
                    {
                        foreach (string subdir in Directory.GetDirectories(dir))
                        {
                            try
                            {
                                Guid.Parse(Path.GetFileName(subdir));
                                gpoDirs.Add(subdir);
                                Logger.Trace("Found GPO dir " + subdir);
                            }
                            catch (FormatException)
                            {
                                Logger.Trace("Found a dir that isn't a GPO dir " + subdir);
                                //Not a guid, not a GPO.
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        if (Logger != null)
                        {
                            Logger.Error("Failed to list the contents of " + dir);
                            Logger.Error(e.Message);
                        }
                    }
                }
            }
            if (gpoDirs.Count >= 0)
            {
                return gpoDirs;
            }
            throw new SysvolException($"No GPOs found in '{sysvolPath}'.");
        }

        /// <summary>
        /// Enumerates the SYSVOL and returns a list of parsed GPOs.
        /// </summary>
        /// <remarks>
        /// Walks the directory and finds the files that we care about.
        /// Parses the files and constructs the GPO based on thei content.
        /// </remarks>
        /// <param name="gpoDirs">
        /// List of GPo directories.
        /// </param>
        /// <returns>
        /// List of parsed GPOs.
        /// </returns>
        private List<GPO> EnumerateSysvolGpos(List<string> gpoDirs)
        {
            List<GPO> gpos = new List<GPO>();
            FileSystemEnumerator fe = new FileSystemEnumerator();
            // for each gpo directory
            foreach (string gpoDir in GpoDirs)
            {
                Logger.Trace("Looking for GP Setting files in " + gpoDir);

                GPO morphedGpo = new GPO(Path.GetFileName(gpoDir), gpoDir, true);
                GPO gpo = new GPO(Path.GetFileName(gpoDir), gpoDir, false);

                // For each file in PathInSysvol and all subdirectories.
                List<string> filesInGpo = new List<string>(fe.ListAllFiles(gpoDir));
                foreach (string file in filesInGpo)
                {
                    Logger.Trace("Looking inside file " + file + " for settings.");
                    try
                    {
                        // Get the file and its settings
                        GpoFile gpoFile = GpoFileFactory.GetFile(file, Logger);
                        gpoFile.Parse();
                        // File only gets added if it is successfully parsed.
                        if (file.ToLower().Contains("ntfrs"))
                        {
                            morphedGpo.GpoFiles.Add(file);
                            sortSettings(morphedGpo, gpoFile);
                        }
                        else
                        {
                            gpo.GpoFiles.Add(file);
                            sortSettings(gpo, gpoFile);
                        }
                    }
                    catch (FileFactoryException e)
                    {
                        if (Logger != null)
                        {
                            Logger.Error($"Issue Parsing '{gpoDir}': {e.Message}");
                        }
                        // Log this and proceed, it's not a dealbreaker.
                    }
                    catch (NotImplementedException e)
                    {
                        if (Logger != null)
                        {
                            Logger.Degub(e.Message);
                        }
                    }
                    catch (Exception e)
                    {
                        if (Logger != null)
                        {
                            Logger.Error("Failure parsing file " + file);
                            Logger.Error(e.Message);
                        }
                    }
                }
                if (gpo.Settings.Count >= 1)
                {
                    gpos.Add(gpo);
                }
                if (morphedGpo.Settings.Count >= 1)
                {
                    gpos.Add(morphedGpo);
                }
                // TODO: Handle other file IO errors here.
            }
            return gpos;
        }

        /// <summary>
        /// Takes a GPO and a GpoFile and adds the parsed settings and findings to the GPO.
        /// </summary>
        /// <param name="gpo">
        /// A GPO
        /// </param>
        /// <param name="gpoFile">
        /// A gpoFile to have it's contents added to the GPO
        /// </param>
        private void sortSettings(GPO gpo, GpoFile gpoFile)
        {
            if (gpoFile.Settings.Count > 0)
            {
                // sort them into either machine or user policy
                if (gpoFile.Info.FullName.ToLower().Contains(Path.DirectorySeparatorChar + "machine" + Path.DirectorySeparatorChar))
                {
                    foreach (GpoSetting gpoSetting in gpoFile.Settings)
                    {
                        gpoSetting.PolicyType = PolicyType.Computer;
                        gpo.Settings.Add(gpoSetting);
                    }
                }
                else if (gpoFile.Info.FullName.ToLower().Contains(Path.DirectorySeparatorChar + "user" + Path.DirectorySeparatorChar))
                {
                    foreach (GpoSetting gpoSetting in gpoFile.Settings)
                    {
                        gpoSetting.PolicyType = PolicyType.User;
                        gpo.Settings.Add(gpoSetting);
                    }
                }
                else
                {
                    if (Logger != null)
                    {
                        Logger.Degub("Some kind of policy I never done did heard of before? " + gpoFile.Info.FullName);
                    }
                }
            }
            else
            {
                if (Logger != null)
                {
                    Logger.Trace("File " + gpoFile.Info.FullName + " didn't seem to have any interesting settings in it.");
                }
            }
        }
    }
}