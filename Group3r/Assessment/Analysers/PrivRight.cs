using BigFish.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;
using LibSnaffle.Classifiers.Rules;
using System.Collections.Generic;

namespace BigFish.Assessment.Analysers
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
                                        trusteeOption.DisplayName.ToLower().Contains("local service") ||
                                        trusteeOption.DisplayName.ToLower().Equals("service") ||
                                        trusteeOption.DisplayName.ToLower().Equals("nt authority\\service"))
                                    {
                                        if (setting.Privilege == "SeAssignPrimaryTokenPrivilege")
                                        {
                                            break;
                                        }
                                        if (setting.Privilege == "SeImpersonatePrivilege")
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
                                else if (trusteeOption.Target)
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
                    }
                }
            }

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