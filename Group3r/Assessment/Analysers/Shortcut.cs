using System;
using System.Collections.Generic;
using Group3r.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;
using LibSnaffle.Classifiers.Rules;

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
                    findings.Add(new GpoFinding()
                    {
                        FindingReason = "Shortcut points at a file that you can modify.",
                        FindingDetail = "It points to " + setting.TargetPath + " so maybe see what happens if you modify that file.",
                        Triage = Constants.Triage.Red
                    });
                }
                else if (!pathFinding.FileExists && pathFinding.DirectoryExists && pathFinding.DirectoryWritable)
                {
                    findings.Add(new GpoFinding()
                    {
                        FindingReason = "Shortcut points to a file that doesn't exist, in a directory that you can write to.",
                        FindingDetail = "It points to " + setting.TargetPath + " so maybe see what happens if you create that file.",
                        Triage = Constants.Triage.Red
                    });
                }
                else if (!pathFinding.FileExists && !pathFinding.DirectoryExists && !String.IsNullOrWhiteSpace(pathFinding.ParentDirectoryExists) && pathFinding.ParentDirectoryWritable)
                {
                    findings.Add(new GpoFinding()
                    {
                        FindingReason = "Shortcut points to a file that doesn't exist, in a directory that ALSO doesn't exist, but there's a parent directory that DOES exist that you can write to.",
                        FindingDetail = "It points to " + setting.TargetPath + " so maybe see what happens if you create that file.",
                        Triage = Constants.Triage.Red
                    });
                }
            }

            if (setting.StartIn.StartsWith("\\\\"))
            {
                PathFinding pathFinding = pathAnalyser.AnalysePath(setting.StartIn);

                // shortcut uses a startin directory on a network share, we need to look at that.

                if (pathFinding.DirectoryExists && pathFinding.DirectoryWritable)
                {
                    findings.Add(new GpoFinding()
                    {
                        FindingReason = "Shortcut is configured to use a working directory that you can write to.",
                        FindingDetail = "You might be able to pull some DLL sideloading shenanigans in " + setting.StartIn,
                        Triage = Constants.Triage.Yellow
                    });
                }
                else if (!pathFinding.FileExists && !pathFinding.DirectoryExists && !String.IsNullOrWhiteSpace(pathFinding.ParentDirectoryExists) && pathFinding.ParentDirectoryWritable)
                {
                    findings.Add(new GpoFinding()
                    {
                        FindingReason = "Shortcut is configured to use a working directory that doesn't exist, but one of its parent directories DOES, and you can write to it.",
                        FindingDetail = "You might be able to pull some DLL sideloading shenanigans in " + setting.StartIn + " if you create it.",
                        Triage = Constants.Triage.Yellow
                    });
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