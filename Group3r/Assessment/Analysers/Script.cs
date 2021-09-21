using Group3r.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;
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
                            FindingReason = "Scheduled Task exec action has an arguments setting that looks like it might have a password in it?",
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

            PathFinding pathFinding = pathAnalyser.AnalysePath(path);

            if (pathFinding != null)
            {
                // if the path points to a file and we can write to it, that's a finding
                if (pathFinding.FileExists && pathFinding.FileWritable)
                {
                    findings.Add(new GpoFinding()
                    {
                        PathFindings = new List<PathFinding>() { pathFinding },
                        FindingReason = "Writable " + setting.ScriptType.ToString() + " script file identified at " + pathFinding.AssessedPath,
                        FindingDetail = "This script will run in the context of the users/computers to which this GPO is applied. Change the script, get command exec as those users/computers.",
                        Triage = Constants.Triage.Black
                    }); ;
                }
                // if the path points to a dir and we can write to it, that's a lesser finding
                if (pathFinding.DirectoryExists && pathFinding.DirectoryWritable)
                {
                    if ((int)MinTriage < 2)
                    {
                        findings.Add(new GpoFinding()
                        {
                            PathFindings = new List<PathFinding>() { pathFinding },
                            FindingReason = "Honestly this looks like a misconfigured " + setting.ScriptType.ToString() + " script setting in a GPO or a bug in Group3r.",
                            FindingDetail = "Script settings should basically never point directly at a dir.",
                            Triage = Constants.Triage.Green
                        }); ;
                    }
                }
                // if the path points to a dir or a file that doesn't exist, but a parent directory does, and we can write to that, that's a finding
                if (!String.IsNullOrEmpty(pathFinding.ParentDirectoryExists) && pathFinding.ParentDirectoryWritable)
                {
                    if ((int)MinTriage < 4)
                    {
                        findings.Add(new GpoFinding()
                        {
                            PathFindings = new List<PathFinding>() { pathFinding },
                            FindingReason = "Missing " + setting.ScriptType.ToString() + " script with a writable parent dir identified at " + pathFinding.ParentDirectoryExists + ". The original target path was " + pathFinding.AssessedPath,
                            FindingDetail = "Recreate the missing parts of the path in the parent dir, put your code in the script. It will then run in the context of the users/computers to which this GPO is applied.",
                            Triage = Constants.Triage.Red
                        }); ;
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