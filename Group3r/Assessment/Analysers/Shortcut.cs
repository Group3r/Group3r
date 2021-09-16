using Group3r.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;
using LibSnaffle.Classifiers.Rules;
using System;
using System.Collections.Generic;

namespace Group3r.Assessment.Analysers
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
                PathFinding pathFinding = pathAnalyser.AnalysePath(setting.TargetPath);

                if (pathFinding.FileExists && pathFinding.FileWritable)
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
                else if (!pathFinding.FileExists && pathFinding.DirectoryExists && pathFinding.DirectoryWritable)
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
                else if (!pathFinding.FileExists && !pathFinding.DirectoryExists && !String.IsNullOrWhiteSpace(pathFinding.ParentDirectoryExists) && pathFinding.ParentDirectoryWritable)
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

            if (setting.StartIn.StartsWith("\\\\"))
            {
                PathFinding pathFinding = pathAnalyser.AnalysePath(setting.StartIn);

                // shortcut uses a startin directory on a network share, we need to look at that.

                if (pathFinding.DirectoryExists && pathFinding.DirectoryWritable)
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
                else if (!pathFinding.FileExists && !pathFinding.DirectoryExists && !String.IsNullOrWhiteSpace(pathFinding.ParentDirectoryExists) && pathFinding.ParentDirectoryWritable)
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

            // make a new setting object minus the ugly bits we don't care about.

            SettingResult.Setting = setting;

            return SettingResult;
        }
    }
}