using Group3r.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;
using LibSnaffle.Classifiers.Rules;
using System;
using System.Collections.Generic;

namespace Group3r.Assessment.Analysers
{
    public class DriveAnalyser : Analyser
    {
        public DriveSetting setting { get; set; }

        public override SettingResult Analyse(AssessmentOptions assessmentOptions)
        {
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

            // put findings in settingResult
            SettingResult.Findings = findings;

            // make a new setting object minus the ugly bits we don't care about.
            //SettingResult.Setting = CleanupSetting(setting);
            SettingResult.Setting = CleanupSetting(setting);

            return SettingResult;
        }


        public DriveSetting CleanupSetting(DriveSetting setting)
        {
            DriveSetting cleanSetting = new DriveSetting();

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

            if (!String.IsNullOrWhiteSpace(setting.Path))
            {
                cleanSetting.Path = setting.Path;
            }

            if (!String.IsNullOrWhiteSpace(setting.Label))
            {
                cleanSetting.Label = setting.Label;
            }

            return cleanSetting;
        }

    }
}