using Group3r.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Group3r.Assessment.Analysers
{
    public class NtServiceAnalyser : Analyser
    {
        public NtServiceSetting setting { get; set; }

        public override SettingResult Analyse(AssessmentOptions assessmentOptions)
        {
            List<GpoFinding> findings = new List<GpoFinding>();

            List<string> modRights = new List<string>() { "WRITE_DAC", "WRITE_OWNER", "SERVICE_CHANGE_CONFIG" };

            if (setting.ParsedSddl != null)
            {
                // Parse the SDDL into a workable format
                List<SimpleAce> analysedSddl = new SddlAnalyser(assessmentOptions).AnalyseSddl(setting.ParsedSddl);

                foreach (SimpleAce simpleAce in analysedSddl)
                {
                    bool grantsWrite = false;
                    bool denyRight = false;

                    foreach (string right in simpleAce.Rights)
                    {
                        if (modRights.Contains(right))
                        {
                            grantsWrite = true;
                        }
                    }

                    // check if it's allow or deny
                    if (simpleAce.ACEType == ACEType.Deny) { denyRight = true; }

                    if (denyRight) { continue; } // TODO actually handle deny rights properly

                    TrusteeOption match = new TrusteeOption();
                    //see if the trustee is a users/group we know about.
                    if (simpleAce.Trustee.DisplayName != null)
                    {
                        IEnumerable<TrusteeOption> nameMatches = assessmentOptions.TrusteeOptions.Where(trusteeopt => trusteeopt.DisplayName == simpleAce.Trustee.DisplayName);
                        if (nameMatches.Any()) { match = nameMatches.First(); }
                    }
                    if (simpleAce.Trustee.Sid != null)
                    {
                        IEnumerable<TrusteeOption> sidMatches =
                            assessmentOptions.TrusteeOptions.Where(trusteeopt =>
                                trusteeopt.SID == simpleAce.Trustee.Sid);
                        if (sidMatches.Any()) { match = sidMatches.First(); }
                    }

                    if (match.DisplayName != null)
                    {
                        // check if it's one of the aggravating principals that are both local and domain and windows struggles to distinguish between:
                        if (match.DisplayName == "Administrators" ||
                            match.DisplayName == "Administrator" ||
                            match.DisplayName == "SYSTEM" ||
                            match.DisplayName == "Local System")
                        {
                            continue;
                        }

                        // so if it's a user/group that we know about...
                        if (match.Target || match.LowPriv)
                        {

                            // and it's either canonically low-priv or we are a member of it
                            if (grantsWrite)
                            {
                                findings.Add(new GpoFinding()
                                {
                                    FindingReason = "A Windows service's ACL is being configured to grant abusable permissions to a target trustee.",
                                    FindingDetail = "This should allow local privilege escalation on affected hosts. Service: " + setting.ServiceName.Replace("\\", "").Replace("\"", "") + ", Trustee: " + match.DisplayName + " - " + match.SID,
                                    Triage = LibSnaffle.Classifiers.Rules.Constants.Triage.Red
                                });
                            }
                        }
                    }
                }
            }

            if (!String.IsNullOrWhiteSpace(setting.Cpassword))
            {
                string password = setting.DecryptCpassword(setting.Cpassword);
                setting.Password = password;
                findings.Add(new GpoFinding()
                {
                    FindingReason = "Group Policy Preferences password found:" + password,
                    FindingDetail = "Refer to MS14-025 and https://adsecurity.org/?p=63",
                    Triage = LibSnaffle.Classifiers.Rules.Constants.Triage.Black
                });
            }

            // put findings in settingResult
            SettingResult.Findings = findings;

            // make a new setting object minus the ugly bits we don't care about.
            SettingResult.Setting = new NtServiceSetting();


            if (setting.Source.Contains("NTFRS"))
            {
                setting.IsMorphed = true;
            }

            SettingResult.Setting = setting;

            return SettingResult;
        }
    }
}