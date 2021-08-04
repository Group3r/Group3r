using System;
using System.Collections.Generic;
using Group3r.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;
using LibSnaffle.Classifiers.Rules;

namespace Group3r.Assessment.Analysers
{
    public class NetOptionAnalyser : Analyser
    {
        public NetOptionSetting setting { get; set; }

        public override SettingResult Analyse(AssessmentOptions assessmentOptions)
        {
            List<GpoFinding> findings = new List<GpoFinding>();
            /*
            findings.Add(new GpoFinding()
            {
                //GpoSetting = setting,
                FindingReason = "NetOption analyser not implemented.",
                FindingDetail = "NetOption analyser not implemented.",
                Triage = Constants.Triage.Green
            });
            
            // put findings in settingResult
            SettingResult.Findings = findings;

            // make a new setting object minus the ugly bits we don't care about.
            SettingResult.Setting = new NetOptionSetting();
            */
            SettingResult.Setting = setting;

            return SettingResult;
        }
    }
}
