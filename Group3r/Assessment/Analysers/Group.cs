using BigFish.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;
using LibSnaffle.Classifiers.Rules;
using System;
using System.Collections.Generic;
using System.Linq;

namespace BigFish.Assessment.Analysers
{
    public class GroupAnalyser : Analyser
    {
        public GroupSetting setting { get; set; }
        public override SettingResult Analyse(AssessmentOptions assessmentOptions)
        {

            List<GpoFinding> findings = new List<GpoFinding>();

            /*
             If we're deleting all users that doesn't give us access
            If they're deleting all groups that doesn't give us access
            If 'removeaccounts' - that doesn't give us access.
            If the group name is a privileged one and they're renaming it - green finding
            if the group name is a privileged one and they're adding a big group or a group we're in - red finding
            if the group name is administrators and they're adding a big group or a group we're in, black finding
             */

            TrusteeOption group = new TrusteeOption();

            try
            {
                if (setting.Name.StartsWith("S-"))
                {
                    group = assessmentOptions.TrusteeOptions.Where(trusteeOption => trusteeOption.SID.Equals(setting.Name, StringComparison.OrdinalIgnoreCase)).First();
                }
                else if ((setting.GroupSid != null) && setting.GroupSid.StartsWith("S-"))
                {
                    group = assessmentOptions.TrusteeOptions.Where(trusteeOption => trusteeOption.SID.Equals(setting.GroupSid, StringComparison.OrdinalIgnoreCase)).First();
                }
                else
                {
                    group = assessmentOptions.TrusteeOptions.Where(trusteeOption => trusteeOption.DisplayName.Equals(setting.Name, StringComparison.OrdinalIgnoreCase)).First();
                }
            }
            catch (Exception e)
            {
                Mq.Trace("Group " + setting.Name + " threw an error trying to match it to a well known name or well known sid." + e.ToString());
                group.DisplayName = setting.Name;
            }

            // if it's not one of these it's not a finding
            if ((setting.Action == SettingAction.Add) || (setting.Action == SettingAction.Update) || (setting.Action == SettingAction.Create))
            {
                // if any of these are true, it's not a finding
                if ((setting.DeleteAllGroups == false) && (setting.DeleteAllUsers == false) && (setting.RemoveAccounts == false))
                {
                    // 
                    if (!String.IsNullOrEmpty(setting.NewName) && group.HighPriv)
                    {
                        if ((int)MinTriage < 2)
                        {
                            findings.Add(new GpoFinding()
                            {
                                //GpoSetting = setting,
                                FindingReason = "A privileged local group is being renamed.",
                                FindingDetail = "Group " + group.DisplayName + " is being renamed to " + setting.NewName,
                                Triage = Constants.Triage.Green
                            });
                        }
                    }
                    // if there's no members, who cares?
                    if (setting.Members.Count > 0)
                    {
                        foreach (GroupSettingMember gsMember in setting.Members)
                        {
                            TrusteeOption toMember = new TrusteeOption();
                            try
                            {
                                if (gsMember.Name.StartsWith("S-"))
                                {
                                    toMember = assessmentOptions.TrusteeOptions.Where(trusteeOption => trusteeOption.SID.Equals(gsMember.Name, StringComparison.OrdinalIgnoreCase)).First();
                                }
                                else
                                {
                                    toMember = assessmentOptions.TrusteeOptions.Where(trusteeOption => trusteeOption.DisplayName.Equals(gsMember.Name, StringComparison.OrdinalIgnoreCase)).First();
                                }
                            }
                            catch (InvalidOperationException e)
                            {
                                // Mq.Trace("User didn't parse to a well known name or well known sid")
                            }
                            catch (Exception e)
                            {
                                Mq.Trace("Something else went fucky with parsing " + gsMember.Name);
                            }
                            // if it's a high priv group and we're adding a low priv trustee, that's a red
                            bool alreadyred = false;
                            if (toMember.LowPriv && group.HighPriv)
                            {
                                alreadyred = true;
                                if ((int)MinTriage < 4)
                                {
                                    findings.Add(new GpoFinding()
                                    {
                                        //GpoSetting = setting,
                                        FindingReason = "A privileged local group is having a low-priv member added to it.",
                                        FindingDetail = "Group " + group.DisplayName + " is having " + toMember.DisplayName + " added to it.",
                                        Triage = Constants.Triage.Red
                                    });
                                }
                            }

                            // if it's a high priv group and we're adding any other trustee, that's a yellow
                            // we do !toMember.HighPriv because we need it to work whether toMember is resolved to a well known sid or not..
                            if (group.HighPriv && !toMember.HighPriv && !alreadyred)
                            {
                                if ((int)MinTriage < 2)
                                {
                                    findings.Add(new GpoFinding()
                                    {
                                        //GpoSetting = setting,
                                        FindingReason = "A privileged local group is having a member added to it. Might be interesting, hard to say.",
                                        FindingDetail = "Group " + group.DisplayName + " is having " + gsMember.Name + " added to it.",
                                        Triage = Constants.Triage.Green
                                    });
                                }
                            }
                        }
                    }
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