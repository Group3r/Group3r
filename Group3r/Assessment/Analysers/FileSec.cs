using Group3r.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;
using System.Collections.Generic;

namespace Group3r.Assessment.Analysers
{
    public class FileSecAnalyser : Analyser
    {
        public FileSecuritySetting setting { get; set; }

        public override SettingResult Analyse(AssessmentOptions assessmentOptions)
        {
            List<GpoFinding> findings = new List<GpoFinding>();

            if (setting.Source.Contains("NTFRS"))
            {
                setting.IsMorphed = true;
            }

            // put findings in settingResult
            SettingResult.Findings = findings;
            SettingResult.Setting = setting;

            return SettingResult;
        }

    }
}
