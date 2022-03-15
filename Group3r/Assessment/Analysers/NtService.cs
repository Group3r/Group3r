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

            if (setting.ParsedSddl != null)
            {
                // Parse the SDDL into a workable format
                List<SimpleAce> analysedSddl = new SddlAnalyser(assessmentOptions).AnalyseSddl(setting.ParsedSddl);

                foreach (SimpleAce simpleAce in analysedSddl)
                {
                    //bool grantsRead = false;
                    bool grantsWrite = false;
                    bool grantsModify = false;
                    bool denyRight = false;
                    //see if any of the rights are interesting
                    foreach (string right in simpleAce.Rights)
                    {
                        /*
                        //if (ReadRights.Contains(right)) { grantsRead = true; }
                        if (WriteRights.Contains(right))
                        {
                            grantsWrite = true;
                        }
                        if (ModifyRights.Contains(right)) { grantsModify = true; }
                        */
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
                    /*
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
                            //set rwStatus based on it.
                            if (grantsModify)
                            {
                                rwStatus.CanModify = true;
                            }
                            if (grantsWrite)
                            {
                                rwStatus.CanWrite = true;
                            }
                            if (grantsModify || grantsWrite)
                            {
                                fsAclResult.InterestingAces.Add(simpleAce);
                            }
                            
                        }
                        else if (!match.HighPriv)
                        {
                            fsAclResult.InterestingAces.Add(simpleAce);
                            if (grantsModify || grantsWrite)
                            {
                                fsAclResult.InterestingAces.Add(simpleAce);
                            }
                        }
                    }
                    else
                    {
                        // otherwise there's no match.
                        if (grantsModify || grantsWrite)
                        {
                            fsAclResult.InterestingAces.Add(simpleAce);
                        }
                    }
                    */
                }
                //fsAclResult.RwStatus = rwStatus;
                //return fsAclResult;
            }
            else
            {
                throw new Exception("NT Service ACL not read/parsed properly.");
            }

            /*
            findings.Add(new GpoFinding()
            {
                //GpoSetting = setting,
                FindingReason = "NtService analyser not implemented.",
                FindingDetail = "NtService analyser not implemented.",
                Triage = Constants.Triage.Green
            });
            */

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