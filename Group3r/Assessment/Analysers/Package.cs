using Group3r.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;
using LibSnaffle.Classifiers.Rules;
using System;
using System.Collections.Generic;

namespace Group3r.Assessment.Analysers
{
    public class PackageAnalyser : Analyser
    {
        public PackageSetting setting { get; set; }

        public override SettingResult Analyse(AssessmentOptions assessmentOptions)
        {
            List<GpoFinding> findings = new List<GpoFinding>();

            PathAnalyser pathAnalyser = new PathAnalyser(assessmentOptions);

            foreach (string msiPath in setting.MsiFileList)
            {
                if (!String.IsNullOrWhiteSpace(msiPath))
                {
                    if (msiPath.StartsWith("\\\\"))
                    {
                        // shortcut targets a network share, we need to look at that
                        PathResult pathResult = pathAnalyser.AnalysePath(msiPath);

                        if (pathResult != null)
                        {
                            if (pathResult.FileExists && pathResult.FileWritable)
                            {
                                if ((int)MinTriage < 4)
                                {
                                    findings.Add(new GpoFinding()
                                    {
                                        FindingReason = "MSI package installer setting points at a file that you can modify.",
                                        FindingDetail = "It points to " + msiPath + " so maybe see what happens if you replace that file with something fun.",
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
                                        FindingReason = "MSI package installer points to a file that doesn't exist, in a directory that you can write to.",
                                        FindingDetail = "It points to " + msiPath + " so maybe see what happens if you put something fun in there.",
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
                                        FindingReason = "MSI package installer points to a file that doesn't exist, in a directory that ALSO doesn't exist, but there's a parent directory that DOES exist that you can write to.",
                                        FindingDetail = "It points to " + msiPath + " so maybe see what happens if you create that file.",
                                        Triage = Constants.Triage.Red
                                    });
                                }
                            }
                        }
                    }
                }
            }

            SettingResult.Findings = findings;
            SettingResult.Setting = setting;

            return SettingResult;
        }
    }
}