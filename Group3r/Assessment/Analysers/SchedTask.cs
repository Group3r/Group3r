using Group3r.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;
using LibSnaffle.Classifiers.Results;
using LibSnaffle.Classifiers.Rules;
using System;
using System.Collections.Generic;

namespace Group3r.Assessment.Analysers
{
    public class SchedTaskAnalyser : Analyser
    {
        public SchedTaskSetting setting { get; set; }
        public override SettingResult Analyse(AssessmentOptions assessmentOptions)
        {
            List<GpoFinding> findings = new List<GpoFinding>();

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
                                PathResult pathResult = pathAnalyser.AnalysePath(schedTaskExecAction.WorkingDir);

                                // schedtask uses a startin directory on a network share, we need to look at that.

                                if (pathResult.DirectoryExists && pathResult.DirectoryWritable)
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
                                else if (!pathResult.FileExists && !pathResult.DirectoryExists && !String.IsNullOrWhiteSpace(pathResult.ParentDirectoryExists) && pathResult.ParentDirectoryWritable)
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

                                if ((int)MinTriage < 3)
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
                                PathResult pathResult = pathAnalyser.AnalysePath(schedTaskExecAction.Command);

                                if (pathResult.FileExists && pathResult.FileWritable)
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
                                else if (!pathResult.FileExists && pathResult.DirectoryExists && pathResult.DirectoryWritable)
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
                                else if (!pathResult.FileExists && !pathResult.DirectoryExists && !String.IsNullOrWhiteSpace(pathResult.ParentDirectoryExists) && pathResult.ParentDirectoryWritable)
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

                                // if the path points to a dir or a file that exist and snaffler deems them interesting, that's a finding on its own, regardless of whether they're modifiable
                                if (pathResult.SnaffDirResults.Count > 0)
                                {
                                    foreach (DirResult dr in pathResult.SnaffDirResults)
                                    {
                                        if (dr.MatchedRule != null)
                                        {
                                            if ((int)MinTriage <= (int)dr.Triage)
                                            {
                                                findings.Add(new GpoFinding()
                                                {
                                                    PathFindings = new List<PathResult>() { pathResult },
                                                    FindingReason =
                                                        "The Snaffler engine deemed this directory path interesting on its own.",
                                                    FindingDetail = "Matched Path: " + dr.ResultDirInfo.FullName + " Matched Rule: " + dr.MatchedRule.RuleName,
                                                    Triage = dr.Triage
                                                });
                                            }
                                        }
                                    }
                                }
                                if (pathResult.SnaffFileResults.Count > 0)
                                {
                                    foreach (FileResult fr in pathResult.SnaffFileResults)
                                    {
                                        if (fr.MatchedRule != null)
                                        {
                                            if ((int)MinTriage <= (int)fr.Triage)
                                            {
                                                findings.Add(new GpoFinding()
                                                {
                                                    PathFindings = new List<PathResult>() { pathResult },
                                                    FindingReason =
                                                        "The Snaffler engine deemed this file path interesting on its own.",
                                                    FindingDetail = "Matched Path: " + fr.ResultFileInfo.FullName + " Matched Rule: " + fr.MatchedRule.RuleName + " Match Context: " + fr.TextResult.MatchContext,
                                                    Triage = fr.Triage
                                                });
                                            }
                                        }
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
                    else if (action.GetType() == typeof(SchedTaskShowMessageAction))
                    {
                        Mq.Trace("Scheduled tasks that just show messages probably aren't worth a finding. Also I've never seen this used IRL.");
                    }
                    else
                    {
                        Mq.Error("Unknown Scheduled Task action type.");
                    }
                }
            }

            SettingResult.Findings = findings;

            if (setting.Source.Contains("NTFRS"))
            {
                setting.IsMorphed = true;
            }

            SettingResult.Setting = setting;

            return SettingResult;
        }
    }
}