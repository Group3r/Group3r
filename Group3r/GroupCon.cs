using Group3r.Assessment;
using Group3r.Assessment.Analysers;
using Group3r.Concurrency;
using Group3r.Options;
using LibSnaffle.ActiveDirectory;
using LibSnaffle.Concurrency;
using LibSnaffle.Errors;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Principal;
using System.Threading;
using System.Timers;
using Timer = System.Timers.Timer;

namespace Group3r
{
    /**
     * Summary: 
     */
    public class GroupCon
    {
        private GrouperMq Mq { get; set; }
        private static BlockingStaticTaskScheduler GpoTaskScheduler;
        private GrouperOptions Options { get; set; }

        public GroupCon(GrouperOptions options, GrouperMq mq)
        {
            Options = options;
            Mq = mq;

            GpoTaskScheduler = new BlockingStaticTaskScheduler(Options.MaxSysvolThreads, Options.MaxSysvolQueue);
        }

        /**
         * Summary: This is the main execution thread.
         * TODO: Clean up the timing.
         */
        public void Execute()
        {
            // Set the time (1 min in this case)
            DateTime startTime = DateTime.Now;
            Timer statusUpdateTimer = new Timer(TimeSpan.FromMinutes(1).TotalMilliseconds) { AutoReset = true };
            statusUpdateTimer.Elapsed += TimedStatusUpdate;
            statusUpdateTimer.Start();

            // Figure out how we're going to load up all our AD/Sysvol info:
            SysvolHelper svh = new SysvolHelper(Mq);
            ActiveDirectory ad = null;

            if (Options.OfflineMode)
            {
                // make sure the user gave us a sysvol target for offline mode to work
                if (string.IsNullOrEmpty(Options.SysvolPath))
                {
                    throw new SysvolException("Offline mode requires a SYSVOL Path. Use -y.");
                }
                Mq.Trace("Loading Sysvol Offline");
                // Manually load SYSVOL offline.
                Sysvol sysvol = svh.LoadSysvolOffline(Options.SysvolPath);
                // make an empty AD object
                ad = new ActiveDirectory(Mq)
                {
                    // stick our sysvol in it
                    Sysvol = sysvol
                };
                // and merge them straight into the slot in AD - no point calling ConsolidateGpos() as there's no AD data there.
                ad.Gpos = ad.Sysvol.Gpos;
            }
            else
            {
                Mq.Trace("building ActiveDirectory");
                try
                {
                    ad = new ActiveDirectory(Mq, Options.TargetDomain, Options.TargetDc);

                    Mq.Trace("Enumerating current user's name and group memberships.");
                    if (Options.AssessmentOptions.TargetTrustees == null)
                    {
                        string thing = WindowsIdentity.GetCurrent().Name;
                        Options.AssessmentOptions.TargetTrustees = new List<string>() {thing};
                    }

                    Mq.Degub("Getting GPOs.");
                    ad.ObtainDomainGpos();
                    Mq.Degub("Loading files from SYSVOL.");
                    ad.LoadSysvolOnline(svh);
                    Mq.Degub("Consolidating GPOs.");
                    ad.ConsolidateGpos();
                }
                catch (Exception e)
                {
                    Mq.Error(e.ToString());
                    while (true)
                    {
                        Mq.Terminate();
                    }
                }
            }
            Mq.Trace("Enqueuing GPO Tasks");
            EnqueueGpoTasks(ad);

            // TODO: snafflers reporting and spinlock is prob better, copy it here.
            while (!GpoTaskScheduler.Done())
            {
                StatusUpdate();
                Thread.Sleep(1000);
            }

            // Finish off timing.
            DateTime finished = DateTime.Now;
            TimeSpan runSpan = finished.Subtract(startTime);
            Mq.Info("Finished at " + finished.ToLocalTime());
            Mq.Info("Group3rin' took " + runSpan);
            Mq.Finish();
        }


        /**
         * Summary: Enqueues tasks to analyse GPOs.
         */
        private void EnqueueGpoTasks(ActiveDirectory Ad)
        {
            // CliMessageProcessor is the only implementation
            // Enqueue all of the GPO tasks.

            AnalyserFactory analyserFactory = new AnalyserFactory();

            foreach (GPO gpo in Ad.Gpos)
            {
                GpoTaskScheduler.New(() =>
                {
                    try
                    {
                        Mq.Trace("Analysing " + gpo.Attributes.PathInSysvol);
                        // make the result object and put the attributes in it.
                        GpoResult gpoResult = new GpoResult(Options.AssessmentOptions, gpo.Attributes);

                        foreach (GpoSetting setting in gpo.Settings)
                        {
                            try
                            {
                                Mq.Trace("Analysing setting from " + setting.Source);
                                Analyser anal = analyserFactory.GetAnalyser(setting);

                                if (anal != null)
                                {
                                    anal.Mq = Mq;
                                    anal.MinTriage = Options.AssessmentOptions.MinTriage;
                                    // have analyser return settingResult

                                    SettingResult settingResult = anal.Analyse(Options.AssessmentOptions);

                                    // if it didn't have a finding, and we haven't specified that we only want findings, stick the setting in settings.
                                    if ((settingResult.Findings.Count == 0) && !Options.FindingsOnly)
                                    {
                                        if (gpoResult.SettingResults == null)
                                        {
                                            gpoResult.SettingResults = new List<SettingResult>();
                                        }
                                        gpoResult.SettingResults.Add(settingResult);
                                    }
                                    else if (settingResult.Findings.Count > 0)
                                    {
                                        if (gpoResult.SettingResults == null)
                                        {
                                            gpoResult.SettingResults = new List<SettingResult>();
                                        }
                                        gpoResult.SettingResults.Add(settingResult);
                                    }
                                }
                            }
                            catch (Exception e)
                            {
                                Mq.Error("Failure processing setting from " + setting.Source + "/r/n" + e.ToString());
                            }
                        }

                        // Enqueue the output of the analysis for output with both the raw object and the pretty string if we're building one
                        Mq.GpoResult(gpoResult, Options.Printer.OutputGpoResult(gpoResult));
                    }
                    // TODO: Handle exceptions properly here, rethrow fatal ones.
                    catch (Exception e)
                    {
                        Mq.Error("Exception in scanning " + gpo.Attributes.PathInSysvol);
                        Mq.Error(e.ToString());
                    }
                });
            }
        }

        /// <summary>
        /// Adds the snaffler task given a list of files/dirs to snaffle.
        /// TODO: This can be modified so that we enqueue a task as soon as
        /// a file/dir path has been found.
        /// </summary>
        /// <param name="pathsToSnaffle"></param>
        /// 
        /*
        private void EnqueueSnafflerTasks(List<string> pathsToSnaffle)
        {
            // What's this? a Snaffler task in Group3r?????????
            Action<object> fileScanTask = new Action<object>((object qp) =>
            {
                QueueAndPath queuePath = qp as QueueAndPath;
                try
                {
                    // Run all file classifier rules over the file.
                    FileClassifier fileClassifier = new FileClassifier(Mq, ClassifierOptions);
                    foreach (ClassifierRule rule in ClassifierOptions.AllRules.FileClassifierRules)
                    {
                        Result result = fileClassifier.Classify(rule, queuePath.Path);
                        if (result != null)
                        {
                            Mq.FileResult(result.ToString(), (FileResult)result);
                            return;
                        };
                    }
                }
                catch (FileNotFoundException e)
                {
                    Mq.Trace(e.ToString());
                    return;
                }
                catch (UnauthorizedAccessException e)
                {
                    Mq.Trace(e.ToString());
                    return;
                }
                catch (PathTooLongException)
                {
                    Mq.Trace($"{queuePath.Path} path was too long for me to look at.");
                    return;
                }
                catch (Exception e)
                {
                    Mq.Trace(e.ToString());
                    return;
                }
            });

            FileSystemEnumerator fse = new FileSystemEnumerator();
            foreach(string path in pathsToSnaffle)
            {
                fse.WalkScheduler(SnafflerTaskScheduler, path, Mq, fileScanTask);
            }
        }
        */
        /**
         * Summary: This method calls statusUpdate every minute.
         */
        private void TimedStatusUpdate(object sender, ElapsedEventArgs e)
        {
            StatusUpdate();
        }

        // TODO: Remove or implement the below.
        private void StatusUpdate()
        {
            //lock (StatusObjectLocker)
            //{
            // get memory usage for status update
            string memorynumber;
            using (Process proc = Process.GetCurrentProcess())
            {
                long memorySize64 = proc.PrivateMemorySize64;
                memorynumber = BytesToString(memorySize64);
            }
            /*
            TaskCounters shareTaskCounters = ShareTaskScheduler.Scheduler.GetTaskCounters();
            TaskCounters treeTaskCounters = TreeTaskScheduler.Scheduler.GetTaskCounters();

            StringBuilder updateText = new StringBuilder("Status Update: \n");
            updateText.Append("ShareFinder Tasks Completed: " + shareTaskCounters.CompletedTasks + "\n");
            updateText.Append("ShareFinder Tasks Remaining: " + shareTaskCounters.CurrentTasksRemaining + "\n");
            updateText.Append("ShareFinder Tasks Running: " + shareTaskCounters.CurrentTasksRunning + "\n");
            updateText.Append("TreeWalker Tasks Completed: " + treeTaskCounters.CompletedTasks + "\n");
            updateText.Append("TreeWalker Tasks Remaining: " + treeTaskCounters.CurrentTasksRemaining + "\n");
            updateText.Append("TreeWalker Tasks Running: " + treeTaskCounters.CurrentTasksRunning + "\n");
            updateText.Append("FileScanner Tasks Completed: " + fileTaskCounters.CompletedTasks + "\n");
            updateText.Append("FileScanner Tasks Remaining: " + fileTaskCounters.CurrentTasksRemaining + "\n");
            updateText.Append("FileScanner Tasks Running: " + fileTaskCounters.CurrentTasksRunning + "\n");
            updateText.Append(memorynumber + " RAM in use.");

            Mq.Info(updateText.ToString());

            if (FileTaskScheduler.Done() && ShareTaskScheduler.Done() && TreeTaskScheduler.Done())
            {
                AllTasksComplete = true;
            }
            */

        }

        /**
         * Summary: Converts bytes to human readable string.
         * TODO: The should probably live somewhere else.
         */
        private static String BytesToString(long byteCount)
        {
            string[] suf = { "B", "kB", "MB", "GB", "TB", "PB", "EB" }; //Longs run out around EB
            if (byteCount == 0)
                return "0" + suf[0];
            long bytes = Math.Abs(byteCount);
            int place = Convert.ToInt32(Math.Floor(Math.Log(bytes, 1024)));
            double num = Math.Round(bytes / Math.Pow(1024, place), 1);
            return (Math.Sign(byteCount) * num) + suf[place];
        }

    }
}