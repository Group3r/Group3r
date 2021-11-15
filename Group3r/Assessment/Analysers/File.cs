using Group3r.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;
using LibSnaffle.Classifiers.Rules;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Group3r.Assessment.Analysers
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
                    PathFinding pathFinding = pathAnalyser.AnalysePath(fromPath);

                    if (pathFinding != null)
                    {
                        // if the path points to a file and we can write to it, that's a finding
                        if (pathFinding.FileExists && pathFinding.FileWritable)
                        {
                            if ((int)MinTriage < 4)
                            {
                                findings.Add(new GpoFinding()
                                {
                                    PathFindings = new List<PathFinding>() { pathFinding },
                                    FindingReason = "Writable file identified at " + pathFinding.AssessedPath + " to be copied to " + setting.TargetPath,
                                    FindingDetail = "This GPO setting will copy a file from point A to point B. If it's a config file you might be able to modify how an app executes. If it's a script you might be able to modify it before it runs as someone else, if it's an Office doc that supports macros... you get the idea.",
                                    Triage = Constants.Triage.Red
                                });
                            }
                        }
                        // if the path points to a dir and we can write to it, that's a lesser finding
                        if (pathFinding.DirectoryExists && pathFinding.DirectoryWritable)
                        {
                            if ((int)MinTriage < 2)
                            {
                                findings.Add(new GpoFinding()
                                {
                                    PathFindings = new List<PathFinding>() { pathFinding },
                                    FindingReason = "Honestly this looks like a misconfigured GPP File GPO setting, or a bug in Group3r.",
                                    FindingDetail = "This setting type should be for moving a file, it should never point at a dir.",
                                    Triage = Constants.Triage.Green
                                });
                            }
                        }
                        // if the path points to a dir or a file that doesn't exist, but a parent directory does, and we can write to that, that's a finding
                        if (!String.IsNullOrEmpty(pathFinding.ParentDirectoryExists) && pathFinding.ParentDirectoryWritable)
                        {
                            if ((int)MinTriage < 3)
                            {
                                findings.Add(new GpoFinding()
                                {
                                    PathFindings = new List<PathFinding>() { pathFinding },
                                    FindingReason = "A GPP File GPO setting is missing its source file, and it has a writable parent dir identified at " + pathFinding.ParentDirectoryExists + ". The original target path was " + pathFinding.AssessedPath + ". Depending on the file type you might be able to do something fun?",
                                    FindingDetail = "Recreate the missing parts of the path in the parent dir, put bad guy stuff in the file, cross your fingers.",
                                    Triage = Constants.Triage.Yellow
                                });
                            }
                        }

                        // if the path points to a dir or a file that exist and snaffler deems them interesting, that's a finding on its own, regardless of whether they're modifiable
                        if (pathFinding.DirResult != null)
                        {
                            if (pathFinding.DirResult.MatchedRule != null)
                            {
                                if ((int)MinTriage <= (int)pathFinding.DirResult.Triage)
                                {
                                    findings.Add(new GpoFinding()
                                    {
                                        PathFindings = new List<PathFinding>() { pathFinding },
                                        FindingReason = "The Snaffler engine deemed this directory path interesting on its own.",
                                        FindingDetail = "Have a look at the associated PathFinding.",
                                        Triage = pathFinding.DirResult.Triage
                                    });
                                }
                            }
                        }

                        if (pathFinding.FileResult != null)
                        {
                            if (pathFinding.FileResult.MatchedRule != null)
                            {
                                if ((int)MinTriage <= (int)pathFinding.FileResult.Triage)
                                {
                                    findings.Add(new GpoFinding()
                                    {
                                        PathFindings = new List<PathFinding>() { pathFinding },
                                        FindingReason = "The Snaffler engine deemed this file path interesting on its own.",
                                        FindingDetail = "Have a look at the associated PathFinding.",
                                        Triage = pathFinding.FileResult.Triage
                                    });
                                }
                            }
                        }
                    }
                }
            }

            // put findings in settingResult
            SettingResult.Findings = findings;

            // make a new setting object minus the ugly bits we don't care about.
            SettingResult.Setting = setting;

            return SettingResult;
        }

    }
}
