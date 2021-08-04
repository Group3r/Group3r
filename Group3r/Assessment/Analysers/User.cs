using System;
using System.Collections.Generic;
using Group3r.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;
using LibSnaffle.Classifiers.Rules;

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

            // make a new setting object minus the ugly bits we don't care about.
            SettingResult.Setting = CleanupSetting(setting);

            return SettingResult;
        }

        public UserSetting CleanupSetting(UserSetting setting)
        {
            UserSetting cleanSetting = new UserSetting();

            if (!String.IsNullOrWhiteSpace(setting.Source))
            {
                cleanSetting.Source = setting.Source;
            }

            /*
                     public string Name { get; set; }
        public string v { get; set; }
        public string FullName { get; set; }
        public string UserName { get; set; }
        public string Cpassword { get; set; }
        public string Password { get; set; }
        public bool AccountDisabled { get; set; }
        public bool PwNeverExpires { get; set; }
        public SettingAction Action { get; set; }
        public string UserAction { get; set; }
        public string Description { get; set; }
             */

            cleanSetting.PolicyType = setting.PolicyType;

            cleanSetting.Action = setting.Action;

            if (!String.IsNullOrWhiteSpace(setting.Name))
            {
                cleanSetting.Name = setting.Name;
            }

            if (!String.IsNullOrWhiteSpace(setting.NewName))
            {
                cleanSetting.NewName = setting.NewName;
            }

            if (!String.IsNullOrWhiteSpace(setting.FullName))
            {
                cleanSetting.FullName = setting.FullName;
            }

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

            if (setting.AccountDisabled != null)
            {
                cleanSetting.AccountDisabled = setting.AccountDisabled;
            }

            if (setting.PwNeverExpires != null)
            {
                cleanSetting.PwNeverExpires = setting.PwNeverExpires;
            }

            if (!String.IsNullOrWhiteSpace(setting.Description))
            {
                cleanSetting.Description = setting.Description;
            }

            return cleanSetting;
        }
    }
}