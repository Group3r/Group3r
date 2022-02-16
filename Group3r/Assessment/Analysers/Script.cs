using Group3r.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;
using LibSnaffle.Classifiers.Results;
using LibSnaffle.Classifiers.Rules;
using System;
using System.Collections.Generic;
using System.IO;

namespace Group3r.Assessment.Analysers
{
    public class ScriptAnalyser : Analyser
    {
        public ScriptSetting setting { get; set; }

        public override SettingResult Analyse(AssessmentOptions assessmentOptions)
        {
            List<GpoFinding> findings = new List<GpoFinding>();


            // if the script is being run with args that look like creds, that's a finding.
            if (!String.IsNullOrWhiteSpace(setting.Parameters))
            {
                if (setting.Parameters.ToLower().Contains("pass") ||
                    setting.Parameters.ToLower().Contains("pw") ||
                    setting.Parameters.ToLower().Contains("cred") ||
                    setting.Parameters.ToLower().Contains("-p") ||
                    setting.Parameters.ToLower().Contains("/p"))
                {
                    if ((int)MinTriage < 3)
                    {
                        findings.Add(new GpoFinding()
                        {
                            FindingReason = setting.ScriptType.ToString() + " script has an arguments setting that looks like it might have a password in it?",
                            FindingDetail = "Arguments were: " + setting.Parameters,
                            Triage = Constants.Triage.Yellow
                        });
                    }
                }
            }

            PathAnalyser pathAnalyser = new PathAnalyser(assessmentOptions);

            string path = setting.CmdLine;

            if (!Path.IsPathRooted(path))
            {
                // if it's not, we need to construct the full path from the GPO path etc.

                string baseGPOPath = Path.GetDirectoryName(setting.Source);
                string adjustedPath = Path.Combine(baseGPOPath, setting.ScriptType.ToString());
                path = Path.Combine(adjustedPath, setting.CmdLine);
            }

            PathResult pathResult = pathAnalyser.AnalysePath(path);

            if (pathResult != null && pathResult.AssessedPath.StartsWith("\\\\"))
            {
                // if the path points to a file and we can write to it, that's a finding
                if (pathResult.FileExists && pathResult.FileWritable)
                {
                    findings.Add(new GpoFinding()
                    {
                        PathFindings = new List<PathResult>() { pathResult },
                        FindingReason = "Writable " + setting.ScriptType.ToString() + " script file identified at " + pathResult.AssessedPath,
                        FindingDetail = "This script will run in the context of the users/computers to which this GPO is applied. Change the script, get command exec as those users/computers.",
                        Triage = Constants.Triage.Black
                    }); ;
                }
                // if the path points to a dir and we can write to it, that's a lesser finding
                if (pathResult.DirectoryExists && pathResult.DirectoryWritable)
                {
                    if ((int)MinTriage < 2)
                    {
                        findings.Add(new GpoFinding()
                        {
                            PathFindings = new List<PathResult>() { pathResult },
                            FindingReason = "Honestly this looks like a misconfigured " + setting.ScriptType.ToString() + " script setting in a GPO or a bug in Group3r.",
                            FindingDetail = "Script settings should basically never point directly at a dir.",
                            Triage = Constants.Triage.Green
                        }); ;
                    }
                }
                // if the path points to a dir or a file that doesn't exist, but a parent directory does, and we can write to that, that's a finding
                if (!String.IsNullOrEmpty(pathResult.ParentDirectoryExists) && pathResult.ParentDirectoryWritable)
                {
                    if ((int)MinTriage < 4)
                    {
                        findings.Add(new GpoFinding()
                        {
                            PathFindings = new List<PathResult>() { pathResult },
                            FindingReason = "Missing " + setting.ScriptType.ToString() + " script with a writable parent dir identified at " + pathResult.ParentDirectoryExists + ". The original target path was " + pathResult.AssessedPath,
                            FindingDetail = "Recreate the missing parts of the path in the parent dir, put your code in the script. It will then run in the context of the users/computers to which this GPO is applied.",
                            Triage = Constants.Triage.Red
                        }); ;
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

            // put findings in settingResult
            SettingResult.Findings = findings;

            // make a new setting object minus the ugly bits we don't care about.
            SettingResult.Setting = CleanupSetting(setting);

            return SettingResult;
        }
        public ScriptSetting CleanupSetting(ScriptSetting setting)
        {
            ScriptSetting cleanSetting = new ScriptSetting();

            if (!String.IsNullOrWhiteSpace(setting.Source))
            {
                cleanSetting.Source = setting.Source;
            }

            cleanSetting.PolicyType = setting.PolicyType;

            cleanSetting.ScriptType = setting.ScriptType;

            if (!String.IsNullOrWhiteSpace(setting.CmdLine))
            {
                cleanSetting.CmdLine = setting.CmdLine;
            }

            if (!String.IsNullOrWhiteSpace(setting.Parameters))
            {
                cleanSetting.Parameters = setting.Parameters;
            }

            return cleanSetting;
        }
    }
}