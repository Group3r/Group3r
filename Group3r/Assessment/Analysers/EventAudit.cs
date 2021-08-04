using System;
using System.Collections.Generic;
using Group3r.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;
using LibSnaffle.Classifiers.Rules;

namespace Group3r.Assessment.Analysers
{
    public class EventAuditAnalyser : Analyser
    {
        public EventAuditSetting setting { get; set; }
        public override SettingResult Analyse(AssessmentOptions assessmentOptions)
        {
            // Nothing interesting enough in here to merit a 'finding'.

            SettingResult.Setting = setting;

            return SettingResult;
        }
    }
}