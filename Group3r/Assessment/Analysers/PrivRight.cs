using Group3r.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;
using LibSnaffle.Classifiers.Rules;
using System;
using System.Collections.Generic;

namespace Group3r.Assessment.Analysers
{
    public class PrivRightAnalyser : Analyser
    {
        public PrivRightSetting setting { get; set; }
        public override SettingResult Analyse(AssessmentOptions assessmentOptions)
        {
            List<GpoFinding> findings = new List<GpoFinding>();

            // iterate over the known-interesting privrights.
            foreach (PrivRightOption privRight in assessmentOptions.PrivRights)
            {
                if (setting.Privilege == privRight.PrivRightName && (privRight.GrantsRemoteAccess || privRight.LocalPrivesc))
                {
                    foreach (Trustee trustee in setting.Trustees)
                    {
                        string trusteeSidForMatch = trustee.Sid;
                        string[] splitTrustee = trustee.Sid?.Split('-') ?? new string[0];
                        if (splitTrustee.Length == 8)
                        {
                            trusteeSidForMatch = splitTrustee[0] + "-" + splitTrustee[1] + "-" + splitTrustee[2] + "-" + splitTrustee[3] + "-" + "<DOMAIN>" + "-" + splitTrustee[7];
                        }
                        bool matched = false;
                        foreach (TrusteeOption trusteeOption in assessmentOptions.TrusteeOptions)
                        {
                            // if we have a match on either SID or display name
                            if ((trusteeSidForMatch == trusteeOption.SID) || (trustee.DisplayName.ToLower() == trusteeOption.DisplayName.ToLower()))
                            {
                                matched = true;
                                if (trusteeOption.HighPriv)
                                {
                                    // boring
                                    break;
                                }
                                else if (trusteeOption.LowPriv)
                                {
                                    if (trusteeOption.DisplayName.ToLower().Contains("network service") ||
                                        trusteeOption.DisplayName.ToLower().Contains("local service"))
                                    {
                                        if (setting.Privilege == "SeAssignPrimaryTokenPrivilege")
                                        {
                                            break;
                                        }
                                    }

                                    // finding
                                    GpoFinding gpoFinding = new GpoFinding
                                    {
                                        FindingReason = "Well-known low-priv user/group assigned an interesting OS privilege.",
                                        FindingDetail = setting.Privilege + " was assigned to " + trustee.DisplayName + " - " + trustee.Sid,
                                        Triage = Constants.Triage.Black
                                    };
                                    // add details
                                    findings.Add(gpoFinding);
                                }
                                else
                                {
                                    if ((int)MinTriage < 2)
                                    {
                                        // finding
                                        GpoFinding gpoFinding = new GpoFinding
                                        {
                                            FindingReason = "User/group assigned an interesting OS privilege. ",
                                            FindingDetail = setting.Privilege + " was assigned to " + trustee.DisplayName + " - " + trustee.Sid,
                                            Triage = Constants.Triage.Green
                                        };
                                        // add details
                                        findings.Add(gpoFinding);
                                    }
                                }
                                break;
                            }
                        }
                        foreach (string targetuser in assessmentOptions.TargetTrustees)
                        {
                            if (trustee.DisplayName.ToLower() == targetuser)
                            {
                                matched = true;
                                if ((int)MinTriage < 4)
                                {
                                    // finding
                                    GpoFinding gpoFinding = new GpoFinding
                                    {
                                        FindingReason = "Targeted user/group assigned an interesting OS privilege.",
                                        FindingDetail = setting.Privilege + " was assigned to " + trustee.DisplayName + " - " + trustee.Sid,
                                        Triage = Constants.Triage.Red
                                    };
                                    findings.Add(gpoFinding);
                                }
                            }
                        }
                        if (matched == false)
                        {
                            if ((int)MinTriage < 2)
                            {
                                // finding
                                GpoFinding gpoFinding = new GpoFinding
                                {
                                    FindingReason = "User/group assigned an interesting OS privilege. ",
                                    FindingDetail = setting.Privilege + " was assigned to " + trustee.DisplayName + " - " + trustee.Sid,
                                    Triage = Constants.Triage.Green
                                };
                                // add details
                                findings.Add(gpoFinding);
                            }
                        }
                    }
                }
            }

            // put findings in settingResult
            SettingResult.Findings = findings;

            // make a new setting object minus the ugly bits we don't care about.
            SettingResult.Setting = CleanupSetting(setting);
            //SettingResult.Setting = setting;

            return SettingResult;
        }


        public PrivRightSetting CleanupSetting(PrivRightSetting setting)
        {
            PrivRightSetting cleanSetting = new PrivRightSetting();

            if (!String.IsNullOrWhiteSpace(setting.Source))
            {
                cleanSetting.Source = setting.Source;
            }

            cleanSetting.PolicyType = setting.PolicyType;

            if (!String.IsNullOrWhiteSpace(setting.Privilege))
            {
                cleanSetting.Privilege = setting.Privilege;
            }

            cleanSetting.TrusteeSids = null;

            if (setting.Trustees.Count > 0)
            {
                cleanSetting.Trustees = setting.Trustees;
            }

            return cleanSetting;
        }

    }
}