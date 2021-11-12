using Group3r.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;
using LibSnaffle.Classifiers.Rules;
using System;
using System.Collections.Generic;

namespace Group3r.Assessment.Analysers
{
    public class DataSourceAnalyser : Analyser
    {
        public DataSourceSetting setting { get; set; }
        public override SettingResult Analyse(AssessmentOptions assessmentOptions)
        {
            // get any findings
            List<GpoFinding> findings = new List<GpoFinding>();

            if (!String.IsNullOrWhiteSpace(setting.Cpassword))
            {
                string password = setting.DecryptCpassword(setting.Cpassword);
                setting.Password = password;
                findings.Add(new GpoFinding()
                {
                    FindingReason = "Group Policy Preferences password found:" + password,
                    FindingDetail = "Refer to MS14-025 and https://adsecurity.org/?p=63",
                    Triage = Constants.Triage.Black
                });
            }

            if ((int)MinTriage < 2)
            {
                findings.Add(new GpoFinding()
                {
                    FindingReason = "Potentially useful database connection info identified.",
                    FindingDetail = "Could be helpful for targeting other attacks.",
                    Triage = Constants.Triage.Green
                });
            }

            // put findings in settingResult
            SettingResult.Findings = findings;

            // make a new setting object minus the ugly bits we don't care about.
            //SettingResult.Setting = CleanupSetting(setting);
            SettingResult.Setting = setting;

            return SettingResult;
        }
    }
}
