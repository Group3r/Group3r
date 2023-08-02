using BigFish.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;
using LibSnaffle.Classifiers.Results;
using LibSnaffle.Classifiers.Rules;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace BigFish.Assessment.Analysers
{
    public class FileAnalyser : Analyser
    {
        public FileSetting setting { get; set; }

        public override SettingResult Analyse(AssessmentOptions assessmentOptions)
        {
            List<GpoFinding> findings = new List<GpoFinding>();

            PathAnalyser pathAnalyser = new PathAnalyser(assessmentOptions);

            // check if there's abusable file copy operations happening
            if (!String.IsNullOrEmpty(setting.FromPath) && !String.IsNullOrEmpty(setting.TargetPath))
            {
                string fromPath = setting.FromPath;

                if (Char.IsLetter(fromPath.FirstOrDefault()))
                {
                    //Mq.Trace("No point analysing a driveletter cos it's meaningless.");
                }
                else if (Path.IsPathRooted(fromPath))
                {
                    PathResult pathResult = pathAnalyser.AnalysePath(fromPath);

                    if (pathResult != null)
                    {
                        // if the path points to a file and we can write to it, that's a finding
                        if (pathResult.FileExists && pathResult.FileWritable)
                        {
                            if ((int)MinTriage < 4)
                            {
                                findings.Add(new GpoFinding()
                                {
                                    PathFindings = new List<PathResult>() { pathResult },
                                    FindingReason = "Writable file identified at " + pathResult.AssessedPath + " to be copied to " + setting.TargetPath,
                                    FindingDetail = "This GPO setting will copy a file from point A to point B. If it's a config file you might be able to modify how an app executes. If it's a script you might be able to modify it before it runs as someone else, if it's an Office doc that supports macros... you get the idea.",
                                    Triage = Constants.Triage.Red
                                });
                            }
                        }
                        // if the path points to a dir and we can write to it, that's a lesser finding
                        if (pathResult.DirectoryExists && pathResult.DirectoryWritable)
                        {
                            if ((int)MinTriage < 2)
                            {
                                findings.Add(new GpoFinding()
                                {
                                    PathFindings = new List<PathResult>() { pathResult },
                                    FindingReason = "Honestly this looks like a misconfigured GPP File GPO setting, or a bug in BigFish.",
                                    FindingDetail = "This setting type should be for moving a file, it should never point at a dir.",
                                    Triage = Constants.Triage.Green
                                });
                            }
                        }
                        // if the path points to a dir or a file that doesn't exist, but a parent directory does, and we can write to that, that's a finding
                        if (!String.IsNullOrEmpty(pathResult.ParentDirectoryExists) && pathResult.ParentDirectoryWritable)
                        {
                            if ((int)MinTriage < 3)
                            {
                                findings.Add(new GpoFinding()
                                {
                                    PathFindings = new List<PathResult>() { pathResult },
                                    FindingReason = "A GPP File GPO setting is missing its source file, and it has a writable parent dir identified at " + pathResult.ParentDirectoryExists + ". The original target path was " + pathResult.AssessedPath + ". Depending on the file type you might be able to do something fun?",
                                    FindingDetail = "Recreate the missing parts of the path in the parent dir, put bad guy stuff in the file, cross your fingers.",
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
                }
            }

            if (setting.Source.Contains("NTFRS"))
            {
                setting.IsMorphed = true;
            }

            // put findings in settingResult
            SettingResult.Findings = findings;
            SettingResult.Setting = setting;

            return SettingResult;
        }

    }
}
