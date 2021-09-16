using Group3r.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;
using LibSnaffle.Classifiers.Rules;
using System;
using System.Collections.Generic;

namespace Group3r.Assessment.Analysers
{
    public class UserAnalyser : Analyser
    {
        public UserSetting setting { get; set; }
        public override SettingResult Analyse(AssessmentOptions assessmentOptions)
        {
            List<GpoFinding> findings = new List<GpoFinding>();

            if (!String.IsNullOrWhiteSpace(setting.Cpassword))
            {
                string password = setting.DecryptCpassword(setting.Cpassword);
                findings.Add(new GpoFinding()
                {
                    FindingReason = "Group Policy Preferences password found:" + password,
                    FindingDetail = "Refer to MS14-025 and https://adsecurity.org/?p=63",
                    Triage = Constants.Triage.Black
                });
            }
            // put findings in settingResult
            SettingResult.Findings = findings;

            SettingResult.Setting = setting;

            return SettingResult;
        }
        
    }
}