using System;
using System.Collections.Generic;
using Group3r.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;
using LibSnaffle.Classifiers.Rules;

namespace Group3r.Assessment.Analysers
{
    public class FolderAnalyser : Analyser
    {
        public FolderSetting setting { get; set; }
        public override SettingResult Analyse(AssessmentOptions assessmentOptions)
        {
            // Nothing particularly sexy or exciting in here.

            SettingResult.Setting = setting;

            return SettingResult;
        }
    }
}
