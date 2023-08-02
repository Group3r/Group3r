using BigFish.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;
using LibSnaffle.Classifiers.Results;
using LibSnaffle.Classifiers.Rules;
using System;
using System.Collections.Generic;

namespace BigFish.Assessment.Analysers
{
    public class ShortcutAnalyser : Analyser
    {
        public ShortcutSetting setting { get; set; }

        public override SettingResult Analyse(AssessmentOptions assessmentOptions)
        {
            List<GpoFinding> findings = new List<GpoFinding>();

            PathAnalyser pathAnalyser = new PathAnalyser(assessmentOptions);

            if (setting.TargetPath.StartsWith("\\\\"))
            {
                // shortcut targets a network share, we need to look at that
                PathResult pathResult = pathAnalyser.AnalysePath(setting.TargetPath);

                if (pathResult != null)
                {

                    if (pathResult.FileExists && pathResult.FileWritable)
                    {
                        if ((int)MinTriage < 4)
                        {
                            findings.Add(new GpoFinding()
                            {
                                FindingReason = "Shortcut points at a file that you can modify.",
                                FindingDetail = "It points to " + setting.TargetPath + " so maybe see what happens if you modify that file.",
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
                                FindingReason = "Shortcut points to a file that doesn't exist, in a directory that you can write to.",
                                FindingDetail = "It points to " + setting.TargetPath + " so maybe see what happens if you create that file.",
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
                                FindingReason = "Shortcut points to a file that doesn't exist, in a directory that ALSO doesn't exist, but there's a parent directory that DOES exist that you can write to.",
                                FindingDetail = "It points to " + setting.TargetPath + " so maybe see what happens if you create that file.",
                                Triage = Constants.Triage.Red
                            });
                        }
                    }
                }
            }

            if (setting.StartIn.StartsWith("\\\\"))
            {
                PathResult pathResult = pathAnalyser.AnalysePath(setting.StartIn);

                // shortcut uses a startin directory on a network share, we need to look at that.

                if (pathResult.DirectoryExists && pathResult.DirectoryWritable)
                {
                    if ((int)MinTriage < 3)
                    {
                        findings.Add(new GpoFinding()
                        {
                            FindingReason = "Shortcut is configured to use a working directory that you can write to.",
                            FindingDetail = "You might be able to pull some DLL sideloading shenanigans in " + setting.StartIn,
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
                            FindingReason = "Shortcut is configured to use a working directory that doesn't exist, but one of its parent directories DOES, and you can write to it.",
                            FindingDetail = "You might be able to pull some DLL sideloading shenanigans in " + setting.StartIn + " if you create it.",
                            Triage = Constants.Triage.Yellow
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
                                        "The Bridler engine deemed this directory path interesting on its own.",
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
                                        "The Bridler engine deemed this file path interesting on its own.",
                                    FindingDetail = "Matched Path: " + fr.ResultFileInfo.FullName + " Matched Rule: " + fr.MatchedRule.RuleName + " Match Context: " + fr.TextResult.MatchContext,
                                    Triage = fr.Triage
                                });
                            }
                        }
                    }
                }
            }

            if (!String.IsNullOrWhiteSpace(setting.Arguments))
            {
                if (setting.Arguments.Contains("pass") || setting.Arguments.Contains("-p") || setting.Arguments.Contains("/p"))
                {
                    if ((int)MinTriage < 3)
                    {
                        findings.Add(new GpoFinding()
                        {
                            FindingReason = "Shortcut has an arguments setting that looks like it might have a password in it?",
                            FindingDetail = "Arguments were: " + setting.Arguments,
                            Triage = Constants.Triage.Yellow
                        });
                    }
                }
            }

            // put findings in settingResult
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