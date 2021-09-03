using System.Collections.Generic;
using LibSnaffle.ActiveDirectory;
using Group3r.Options.AssessmentOptions;
using Group3r.Concurrency;
using LibSnaffle.Classifiers.Rules;

namespace Group3r.Assessment.Analysers
{
    public abstract class Analyser
    {
        public abstract SettingResult Analyse(AssessmentOptions assessmentOptions);
        public SettingResult SettingResult { get; set; } = new SettingResult();

        public GrouperMq Mq { get; set; }
        public Constants.Triage MinTriage { get; set; }
    }
}