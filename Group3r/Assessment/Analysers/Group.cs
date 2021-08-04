using System;
using System.Collections.Generic;
using Group3r.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;
using LibSnaffle.Classifiers.Rules;

namespace Group3r.Assessment.Analysers
{
    public class GroupAnalyser : Analyser
    {
        public GroupSetting setting { get; set; }
        public override SettingResult Analyse(AssessmentOptions assessmentOptions)
        {
            // Need to write logic to figure out when a group membership is good/fun/interesting and not extremely boring.

            
            List<GpoFinding> findings = new List<GpoFinding>();

            /*
            findings.Add(new GpoFinding()
            {
                //GpoSetting = setting,
                FindingReason = "Group analyser not implemented.",
                FindingDetail = "Group analyser not implemented.",
                Triage = Constants.Triage.Green
            });
            

            // put findings in settingResult
            SettingResult.Findings = findings;

            // make a new setting object minus the ugly bits we don't care about.
            SettingResult.Setting = new GroupSetting();
            */
            SettingResult.Setting = setting;

            return SettingResult;
        }
    }
}