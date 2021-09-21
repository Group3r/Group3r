using Group3r.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;
using LibSnaffle.Classifiers.Rules;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Group3r.Assessment.Analysers
{
    public class SchedTaskAnalyser : Analyser
    {
        public SchedTaskSetting setting { get; set; }
        public override SettingResult Analyse(AssessmentOptions assessmentOptions)
        {
            List<GpoFinding> findings = new List<GpoFinding>();

            /*
            findings.Add(new GpoFinding()
            {
                FindingReason = "SchedTask analyser not implemented.",
                FindingDetail = "SchedTask analyser not implemented.",
                Triage = Constants.Triage.Green
            });
            // put findings in settingResult
            SettingResult.Findings = findings;

            // make a new setting object minus the ugly bits we don't care about.
            SettingResult.Setting = new SchedTaskSetting();
            */

            // if they're specifying who to run the task as
            if (setting.Principals != null)
            {
                if (setting.Principals.Count >= 1)
                {
                    foreach (SchedTaskPrincipal principal in setting.Principals)
                    {
                        if (!String.IsNullOrWhiteSpace(principal.Cpassword))
                        {
                            string password = setting.DecryptCpassword(principal.Cpassword);
                            principal.Password = password;
                            findings.Add(new GpoFinding()
                            {
                                FindingReason = "Group Policy Preferences password found:" + password,
                                FindingDetail = "Refer to MS14-025 and https://adsecurity.org/?p=63",
                                Triage = Constants.Triage.Black
                            });
                        }
                    }
                }
            }

            if (setting.Actions != null)
            {
                foreach (SchedTaskAction action in setting.Actions)
                {
                    if (action.GetType() == typeof(SchedTaskExecAction))
                    {
                        PathAnalyser pathAnalyser = new PathAnalyser(assessmentOptions);

                        SchedTaskExecAction schedTaskExecAction = (SchedTaskExecAction)action;


                        if (schedTaskExecAction.WorkingDir != null)
                        {
                            if (schedTaskExecAction.WorkingDir.StartsWith("\\\\"))
                            {
                                PathFinding pathFinding = pathAnalyser.AnalysePath(schedTaskExecAction.WorkingDir);

                                // schedtask uses a startin directory on a network share, we need to look at that.

                                if (pathFinding.DirectoryExists && pathFinding.DirectoryWritable)
                                {
                                    if ((int)MinTriage < 3)
                                    {
                                        findings.Add(new GpoFinding()
                                        {
                                            FindingReason = "Scheduled task exec action is configured to use a working directory that you can write to.",
                                            FindingDetail = "You might be able to pull some DLL sideloading shenanigans in " + schedTaskExecAction.WorkingDir,
                                            Triage = Constants.Triage.Yellow
                                        });
                                    }
                                }
                                else if (!pathFinding.FileExists && !pathFinding.DirectoryExists && !String.IsNullOrWhiteSpace(pathFinding.ParentDirectoryExists) && pathFinding.ParentDirectoryWritable)
                                {
                                    if ((int)MinTriage < 3)
                                    {
                                        findings.Add(new GpoFinding()
                                        {
                                            FindingReason = "Scheduled task exec action is configured to use a working directory that doesn't exist, but one of its parent directories DOES, and you can write to it.",
                                            FindingDetail = "You might be able to pull some DLL sideloading shenanigans in " + schedTaskExecAction.WorkingDir + " if you create it.",
                                            Triage = Constants.Triage.Yellow
                                        });
                                    }
                                }
                            }
                        }

                        if (!String.IsNullOrWhiteSpace(schedTaskExecAction.Args))
                        {
                            if (schedTaskExecAction.Args.ToLower().Contains("pass") ||
                                schedTaskExecAction.Args.ToLower().Contains("pw") ||
                                schedTaskExecAction.Args.ToLower().Contains("cred") ||
                                schedTaskExecAction.Args.ToLower().Contains("-p") ||
                                schedTaskExecAction.Args.ToLower().Contains("/p"))
                            {

                                if ((int) MinTriage < 3)
                                {
                                    findings.Add(new GpoFinding()
                                    {
                                        FindingReason =
                                            "Scheduled Task exec action has an arguments setting that looks like it might have a password in it?",
                                        FindingDetail = "Arguments were: " + schedTaskExecAction.Args,
                                        Triage = Constants.Triage.Yellow
                                    });
                                }

                            }
                        }

                        if (schedTaskExecAction.Command != null)
                        {
                            if (schedTaskExecAction.Command.StartsWith("\\\\"))
                            {
                                PathFinding pathFinding = pathAnalyser.AnalysePath(schedTaskExecAction.Command);

                                if (pathFinding.FileExists && pathFinding.FileWritable)
                                {
                                    if ((int)MinTriage < 4)
                                    {
                                        findings.Add(new GpoFinding()
                                        {
                                            FindingReason = "Scheduled Task execute action points at a file that you can modify.",
                                            FindingDetail = "It points to " + schedTaskExecAction.Command + ", so maybe see what happens if you modify that file.",
                                            Triage = Constants.Triage.Red
                                        });
                                    }
                                }
                                else if (!pathFinding.FileExists && pathFinding.DirectoryExists && pathFinding.DirectoryWritable)
                                {
                                    if ((int)MinTriage < 4)
                                    {
                                        findings.Add(new GpoFinding()
                                        {
                                            FindingReason = "Scheduled Task execute action points to a file that doesn't exist, in a directory that you can write to.",
                                            FindingDetail = "It points to " + schedTaskExecAction.Command + " so maybe see what happens if you create that file.",
                                            Triage = Constants.Triage.Red
                                        });
                                    }
                                }
                                else if (!pathFinding.FileExists && !pathFinding.DirectoryExists && !String.IsNullOrWhiteSpace(pathFinding.ParentDirectoryExists) && pathFinding.ParentDirectoryWritable)
                                {
                                    if ((int)MinTriage < 4)
                                    {
                                        findings.Add(new GpoFinding()
                                        {
                                            FindingReason = "Scheduled Task execute action points to a file that doesn't exist, in a directory that ALSO doesn't exist, but there's a parent directory that DOES exist that you can write to.",
                                            FindingDetail = "It points to " + schedTaskExecAction.Command + " so maybe see what happens if you create that file.",
                                            Triage = Constants.Triage.Red
                                        });
                                    }
                                }
                            }
                        }
                    }
                    else if (action.GetType() == typeof(SchedTaskEmailAction))
                    {
                        SchedTaskEmailAction schedTaskEmailAction = (SchedTaskEmailAction)action;

                        if (schedTaskEmailAction.Attachments != null)
                        {
                            if (schedTaskEmailAction.Attachments.Count >= 1)
                            {
                                string attachments = "";
                                if (schedTaskEmailAction.Attachments.Count == 1)
                                {
                                    attachments = schedTaskEmailAction.Attachments[0];
                                }
                                else
                                {
                                    foreach (string attachment in schedTaskEmailAction.Attachments)
                                    {
                                        attachments = attachments + ", " + attachment;
                                    }
                                }

                                findings.Add(new GpoFinding()
                                {
                                    FindingReason = "Scheduled Task is emailing attachments. Could be interesting.",
                                    

                                    FindingDetail = "Check out " + attachments,
                                    Triage = Constants.Triage.Green
                                });
                            }
                        }
                    }
                    else
                    {
                        Mq.Error("Unknown Scheduled Task action type.");
                    }
                }
            }

            SettingResult.Findings = findings;
            SettingResult.Setting = setting;

            return SettingResult;
        }
    }
}