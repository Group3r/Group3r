using System;
using System.Collections.Generic;
using Group3r.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;
using LibSnaffle.Classifiers.Rules;

namespace Group3r.Assessment.Analysers
{
    public class SchedTaskAnalyser : Analyser
    {
        public SchedTaskSetting setting { get; set; }
        public override SettingResult Analyse(AssessmentOptions assessmentOptions)
        {
            List<GpoFinding> findings = new List<GpoFinding>();
            /*
            findings.Add(new GpoFinding()
            {
                FindingReason = "SchedTask analyser not implemented.",
                FindingDetail = "SchedTask analyser not implemented.",
                Triage = Constants.Triage.Green
            });
            // put findings in settingResult
            SettingResult.Findings = findings;

            // make a new setting object minus the ugly bits we don't care about.
            SettingResult.Setting = new SchedTaskSetting();
            */
            SettingResult.Setting = setting;

            return SettingResult;
        }
    }
}