using System;
using System.Collections.Generic;
using Group3r.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;
using LibSnaffle.Classifiers.Rules;

namespace Group3r.Assessment.Analysers
{
    public class KerbPolicyAnalyser : Analyser
    {
        public KerbPolicySetting setting { get; set; }

        public override SettingResult Analyse(AssessmentOptions assessmentOptions)
        {
            // TODO - do simple analysis of this for low-sev findings

            /*        MaxTicketAge = 10
        MaxRenewAge = 7
        MaxServiceAge = 600
        MaxClockSkew = 5
        TicketValidateClient = 1
            */

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

            // make a new setting object minus the ugly bits we don't care about.
            SettingResult.Setting = new KerbPolicySetting();
            SettingResult.Setting = setting;

            return SettingResult;
        }
    }
}
