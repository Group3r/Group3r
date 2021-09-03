using System;
using System.Collections.Generic;
using Group3r.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;
using LibSnaffle.Classifiers.Rules;

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
                findings.Add(new GpoFinding()
                {
                    FindingReason = "Group Policy Preferences password found:" + password,
                    FindingDetail = "Refer to MS14-025 and https://adsecurity.org/?p=63",
                    Triage = Constants.Triage.Black
                });
            }

            if ((int)this.MinTriage < 2)
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
        
        public DataSourceSetting CleanupSetting(DataSourceSetting setting)
        {
            DataSourceSetting cleanSetting = new DataSourceSetting();

            if (!String.IsNullOrWhiteSpace(setting.Source))
            {
                cleanSetting.Source = setting.Source;
            }

            cleanSetting.PolicyType = setting.PolicyType;

            if (!String.IsNullOrWhiteSpace(setting.Name))
            {
                cleanSetting.Name = setting.Name;
            }

            cleanSetting.Action = setting.Action;

            if (!String.IsNullOrWhiteSpace(setting.UserName))
            {
                cleanSetting.UserName = setting.UserName;
            }
            if (!String.IsNullOrWhiteSpace(setting.Cpassword))
            {
                cleanSetting.Cpassword = setting.Cpassword;
            }
            if (!String.IsNullOrWhiteSpace(setting.Password))
            {
                cleanSetting.Password = setting.Password;
            }
            if (!String.IsNullOrWhiteSpace(setting.DSN))
            {
                cleanSetting.DSN = setting.DSN;
            }
            if (!String.IsNullOrWhiteSpace(setting.Driver))
            {
                cleanSetting.Driver = setting.Driver;
            }
            if (!String.IsNullOrWhiteSpace(setting.Description))
            {
                cleanSetting.Description = setting.Description;
            }
            cleanSetting.Attributes = setting.Attributes;
            return cleanSetting;
        }
        
    }
}
