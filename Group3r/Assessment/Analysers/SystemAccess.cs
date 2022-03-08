using Group3r.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;
using LibSnaffle.Classifiers.Rules;
using System;
using System.Collections.Generic;

namespace Group3r.Assessment.Analysers
{
    public class SystemAccessAnalyser : Analyser
    {
        public SystemAccessSetting setting { get; set; }

        public override SettingResult Analyse(AssessmentOptions assessmentOptions)
        {
            List<GpoFinding> findings = new List<GpoFinding>();

            if (setting.SettingName == "MinimumPasswordAge")
            {
                if (setting.ValueString != "1")
                {
                    if ((int)MinTriage < 2)
                    {
                        findings.Add(new GpoFinding()
                        {
                            FindingReason = "Non-default minimum password age.",
                            FindingDetail = "Minimum password age is " + setting.ValueString + " days.",
                            Triage = Constants.Triage.Green
                        });
                    }
                }
            }

            else if (setting.SettingName == "MaximumPasswordAge")
            {
                if (setting.ValueString != "42")
                {
                    if ((int)MinTriage < 2)
                    {
                        findings.Add(new GpoFinding()
                        {
                            FindingReason = "Non-default maximum password age.",
                            FindingDetail = "Maximum password age is " + setting.ValueString + " days.",
                            Triage = Constants.Triage.Green
                        });
                    }
                }
            }

            else if (setting.SettingName == "MinimumPasswordLength")
            {
                if (setting.ValueString != "7")
                {
                    if ((int)MinTriage < 2)
                    {
                        findings.Add(new GpoFinding()
                        {
                            FindingReason = "Non-default minimum password length.",
                            FindingDetail = "Minimum password length is " + setting.ValueString + " days.",
                            Triage = Constants.Triage.Green
                        });
                    }
                }
            }

            else if (setting.SettingName == "PasswordComplexity")
            {
                if (setting.ValueString != "1")
                {
                    if ((int)MinTriage < 2)
                    {
                        findings.Add(new GpoFinding()
                        {
                            FindingReason = "Password complexity disabled.",
                            FindingDetail = "",
                            Triage = Constants.Triage.Green
                        });
                    }
                }
            }

            else if (setting.SettingName == "PasswordHistorySize")
            {
                if (setting.ValueString != "24")
                {
                    if ((int)MinTriage < 2)
                    {
                        findings.Add(new GpoFinding()
                        {
                            FindingReason = "Non-default password history size.",
                            FindingDetail = "Password history value is " + setting.ValueString,
                            Triage = Constants.Triage.Green
                        });
                    }
                }
            }

            else if (setting.SettingName == "LockoutBadCount")
            {
                if (setting.ValueString != "5")
                {
                    if ((int)MinTriage < 2)
                    {
                        findings.Add(new GpoFinding()
                        {
                            FindingReason = "Non-default lockout count value.",
                            FindingDetail = "Accounts lock out after " + setting.ValueString + " bad passwords",
                            Triage = Constants.Triage.Green
                        });
                    }
                }
            }

            else if (setting.SettingName == "ResetLockoutCount")
            {
                if (setting.ValueString != "30")
                {
                    if ((int)MinTriage < 2)
                    {
                        findings.Add(new GpoFinding()
                        {
                            FindingReason = "Non-default lockout reset time value.",
                            FindingDetail = "Invalid attempt counter resets after" + setting.ValueString + " minutes.",
                            Triage = Constants.Triage.Green
                        });
                    }
                }
            }

            else if (setting.SettingName == "LockoutDuration")
            {
                if (setting.ValueString != "30")
                {
                    if ((int)MinTriage < 2)
                    {
                        findings.Add(new GpoFinding()
                        {
                            FindingReason = "Non-default lockout duration value.",
                            FindingDetail = "Account unlocks after" + setting.ValueString + " minutes.",
                            Triage = Constants.Triage.Green
                        });
                    }
                }
            }

            else if (setting.SettingName == "ForceLogoffWhenHourExpire")
            {
                if (setting.ValueString != "0")
                {
                    if ((int)MinTriage < 2)
                    {
                        findings.Add(new GpoFinding()
                        {
                            FindingReason = "Force logoff outside hours is enforced.",
                            FindingDetail = "",
                            Triage = Constants.Triage.Green
                        });
                    }
                }
            }

            else if (setting.SettingName == "NewAdministratorName")
            {
                if (!String.IsNullOrEmpty(setting.ValueString))
                {
                    if ((int)MinTriage < 2)
                    {
                        findings.Add(new GpoFinding()
                        {
                            FindingReason = "Local Administrator account name changed.",
                            FindingDetail = "New local Administrator account name is " + setting.ValueString,
                            Triage = Constants.Triage.Green
                        });
                    }
                }
            }

            else if (setting.SettingName == "NewGuestName")
            {
                if (!String.IsNullOrEmpty(setting.ValueString))
                {
                    if ((int)MinTriage < 2)
                    {
                        findings.Add(new GpoFinding()
                        {
                            FindingReason = "Local Guest account name changed.",
                            FindingDetail = "New local Guest account name is " + setting.ValueString,
                            Triage = Constants.Triage.Green
                        });
                    }
                }
            }

            else if (setting.SettingName == "ClearTextPassword")
            {
                if (setting.ValueString != "0")
                {
                    if ((int)MinTriage < 3)
                    {
                        findings.Add(new GpoFinding()
                        {
                            FindingReason = "SAM (or domain if this GPO applies to DCs) passwords stored with reversible encryption.",
                            FindingDetail = "",
                            Triage = Constants.Triage.Yellow
                        });
                    }
                }
            }

            else if (setting.SettingName == "EnableGuestAccount")
            {
                if (setting.ValueString != "0")
                {
                    if ((int)MinTriage < 3)
                    {
                        findings.Add(new GpoFinding()
                        {
                            FindingReason = "Local Guest account enabled.",
                            FindingDetail = "",
                            Triage = Constants.Triage.Yellow
                        });
                    }
                }
            }

            else if (setting.SettingName == "EnableAdminAccount")
            {
                if (setting.ValueString != "1")
                {
                    if ((int)MinTriage < 2)
                    {
                        findings.Add(new GpoFinding()
                        {
                            FindingReason = "Local Administrator account disabled.",
                            FindingDetail = "",
                            Triage = Constants.Triage.Green
                        });
                    }
                }
            }

            else if (setting.SettingName == "RequireLogonToChangePassword")
            {
                if (setting.ValueString != "1")
                {
                    if ((int)MinTriage < 2)
                    {
                        findings.Add(new GpoFinding()
                        {
                            FindingReason = "Expired passwords require admin intervention to reset.",
                            FindingDetail = "",
                            Triage = Constants.Triage.Green
                        });
                    }
                }
            }

            else if (setting.SettingName == "LSAAnonymousNameLookup")
            {
                if (setting.ValueString != "1")
                {
                    if ((int)MinTriage < 2)
                    {
                        findings.Add(new GpoFinding()
                        {
                            FindingReason = "Anonymous users can query the local LSA policy.",
                            FindingDetail = "",
                            Triage = Constants.Triage.Green
                        });
                    }
                }
            }

            else
            {
                throw new NotImplementedException("SystemAccess analyser doesn't know what a " + setting.SettingName + " is.");
            }

            // put findings in settingResult
            SettingResult.Findings = findings;

            if (setting.Source.Contains("NTFRS"))
            {
                setting.IsMorphed = true;
            }

            SettingResult.Setting = setting;

            return SettingResult;
        }
    }
}
