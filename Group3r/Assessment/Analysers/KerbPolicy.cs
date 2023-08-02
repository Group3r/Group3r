using BigFish.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;
using LibSnaffle.Classifiers.Rules;
using System.Collections.Generic;

namespace BigFish.Assessment.Analysers
{
    public class KerbPolicyAnalyser : Analyser
    {
        public KerbPolicySetting setting { get; set; }

        public override SettingResult Analyse(AssessmentOptions assessmentOptions)
        {

            List<GpoFinding> findings = new List<GpoFinding>();

            if (setting.Key == "MaxTicketAge")
            {
                if (setting.Value != "10")
                {
                    findings.Add(new GpoFinding()
                    {
                        //GpoSetting = setting,
                        FindingReason = "Non-default maximum Kerberos ticket age configured. " + setting.Value,
                        FindingDetail = "Dunno, bit interesting.",
                        Triage = Constants.Triage.Green
                    });
                }
            }

            else if (setting.Key == "MaxRenewAge")
            {
                if (setting.Value != "7")
                {
                    findings.Add(new GpoFinding()
                    {
                        //GpoSetting = setting,
                        FindingReason = "Non-default maximum Kerberos renewal period configured. " + setting.Value,
                        FindingDetail = "Dunno, bit interesting.",
                        Triage = Constants.Triage.Green
                    });
                }
            }

            else if (setting.Key == "MaxServiceAge")
            {
                if (setting.Value != "600")
                {
                    findings.Add(new GpoFinding()
                    {
                        //GpoSetting = setting,
                        FindingReason = "Non-default maximum Kerberos service ticket age configured. " + setting.Value,
                        FindingDetail = "Dunno, bit interesting.",
                        Triage = Constants.Triage.Green
                    });
                }
            }

            else if (setting.Key == "MaxClockSkew")
            {
                if (setting.Value != "600")
                {
                    findings.Add(new GpoFinding()
                    {
                        //GpoSetting = setting,
                        FindingReason = "Non-default maximum Kerberos clock skew setting. " + setting.Value,
                        FindingDetail = "Dunno, bit interesting.",
                        Triage = Constants.Triage.Green
                    });
                }
            }

            else if (setting.Key == "TicketValidateClient")
            {
                if (setting.Value != "1")
                {
                    findings.Add(new GpoFinding()
                    {
                        //GpoSetting = setting,
                        FindingReason = "Kerberos 'Enforce user logon restrictions' setting is disabled.",
                        FindingDetail = "Probably no significant impact, read here for more details: https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/enforce-user-logon-restrictions",
                        Triage = Constants.Triage.Green
                    });
                }
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
