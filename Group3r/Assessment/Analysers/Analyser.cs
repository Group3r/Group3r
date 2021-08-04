using System.Collections.Generic;
using LibSnaffle.ActiveDirectory;
using Group3r.Options.AssessmentOptions;

namespace Group3r.Assessment.Analysers
{
    public abstract class Analyser
    {
        public abstract SettingResult Analyse(AssessmentOptions assessmentOptions);
        public SettingResult SettingResult { get; set; } = new SettingResult();
    }
}