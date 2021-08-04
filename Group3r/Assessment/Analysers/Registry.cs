using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using Group3r.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;
using LibSnaffle.Classifiers.Rules;
using Sddl.Parser;
using Trustee = Group3r.Options.AssessmentOptions.TrusteeOption;

namespace Group3r.Assessment.Analysers
{
    public class RegistryAnalyser : Analyser
    {
        public RegistrySetting setting { get; set; }
        public override SettingResult Analyse(AssessmentOptions assessmentOptions)
        {
            List<GpoFinding> findings = new List<GpoFinding>();

            // sometimes it'll be about the permissions on the reg key
            if (setting.ParsedKeySddl != null)
            {
                SddlAnalyser sddlAnalyser = new SddlAnalyser(assessmentOptions);

                List<SimpleAce> simpleAcl = sddlAnalyser.AnalyseSddl(setting.ParsedKeySddl);
                if (simpleAcl.Count > 0)
                {
                    GpoFinding gpoFinding = new GpoFinding();
                    gpoFinding.AclResult = simpleAcl;
                    gpoFinding.FindingReason = "Found some interesting ACEs on the file.";
                    gpoFinding.FindingDetail = "I'm so tired.";
                    findings.Add(gpoFinding);
                }
                // ok who's the owner?
                if (setting.ParsedKeySddl.Owner != null)
                {
                    foreach (TrusteeOption trustee in assessmentOptions.TrusteeOptions)
                    {
                        if ((setting.ParsedKeySddl.Owner.Alias.Equals(trustee.DisplayName)) && (!trustee.HighPriv))
                        {
                            // TODO do proper sid comparisons or something fuck
                            findings.Add(new GpoFinding()
                            {
                                FindingReason =
                                    "The " + trustee.DisplayName + " trustee has been made owner of this registry key.",
                                FindingDetail = "You'll need to take a closer look at this key to know if this has any value at all. Good luck.",
                                Triage = Constants.Triage.Yellow
                            });
                            break;
                        }
                    }
                }
                // ok who got permissions then
                foreach (Ace ace in setting.ParsedKeySddl.Dacl.Aces)
                {
                    // deny settings aren't super interesting
                    if (ace.AceType == "ACCESS_ALLOWED")
                    {
                        bool keyWritable = false;
                        foreach (string right in ace.Rights)
                        {
                            // check if the right being assigned is one that allows interesting access
                            if (right.Equals("KEY_ALL") || right.Equals("KEY_WRITE"))
                            {
                                keyWritable = true;
                            }
                        }

                        foreach (Trustee trustee in assessmentOptions.TrusteeOptions)
                        {
                            if (ace.AceSid.Alias.Equals(trustee.DisplayName))
                            {
                                if (trustee.HighPriv)
                                {
                                    // we don't care if a high priv user has a privilege, that's boring.
                                    break;
                                }
                                if (trustee.LowPriv)
                                {
                                    findings.Add(new GpoFinding()
                                    {
                                        FindingReason =
                                            "The " + trustee.DisplayName + " trustee has been granted additional rights over this registry key.",
                                        FindingDetail = "You'll need to take a closer look at this key to know if this has any value at all. Good luck.",
                                        Triage = Constants.Triage.Yellow
                                    });
                                    break;
                                }
                                findings.Add(new GpoFinding()
                                {
                                    FindingReason =
                                        "The " + trustee.DisplayName + " trustee has been granted additional rights over this registry key.",
                                    FindingDetail = "You'll need to take a closer look at this key to know if this has any value at all. Good luck.",
                                    Triage = Constants.Triage.Green
                                });
                                break;
                            }
                        }
                    }
                }
            }

            // other times it'll be about the value(s)
            foreach (RegKey ruleKey in assessmentOptions.RegKeys)
            {
                if (setting.Key.IndexOf(ruleKey.Key, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    // this is a potentially interesting key
                    foreach (RegistryValue regValue in setting.Values)
                    {
                        // figure out the basis on which the ruleKey is considered 'interesting' and act accordingly.
                        switch (ruleKey.InterestingIf)
                        {
                            case InterestingIf.Present:
                                // some of these won't have a value name at all, only the key.
                                // That's fine, sometimes we're just looking for the presence of a key and the subkeys don't even matter.
                                if ((ruleKey.ValueName == null) || (regValue.ValueName.IndexOf(ruleKey.ValueName, StringComparison.OrdinalIgnoreCase) >= 0))
                                {
                                    findings.Add(new GpoFinding()
                                    {
                                        FindingReason =
                                            "This registry key being present at all is considered interesting.",
                                        FindingDetail = ruleKey.FriendlyDescription + " " + ruleKey.MsDesc,
                                        Triage = ruleKey.Triage
                                    });
                                }
                                break;
                            case InterestingIf.Bad:
                                // these will have to be precise matches
                                if (regValue.ValueName.IndexOf(ruleKey.ValueName, StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    bool interesting = false;
                                    switch (ruleKey.ValueType)
                                    {
                                        case RegKeyValType.REG_DWORD:
                                            int dword;
                                            Int32.TryParse(Encoding.UTF8.GetString(regValue.ValueBytes, 0,
                                                regValue.ValueBytes.Length), out dword); 
                                            interesting = IsInterestingBecauseBad(ruleKey.BadDword, dword);
                                            break;
                                        case RegKeyValType.REG_BINARY:
                                            interesting = IsInterestingBecauseBad(ruleKey.BadBinary,
                                                regValue.ValueBytes);
                                            break;
                                        case RegKeyValType.REG_SZ:
                                            interesting = IsInterestingBecauseBad(ruleKey.BadSz,
                                                regValue.ValueString);
                                            break;
                                        default:
                                            throw new NotImplementedException("No code to handle rules around " +
                                                                              ruleKey.ValueType.ToString() + " keys.");
                                    }

                                    if (interesting)
                                    {
                                        findings.Add(new GpoFinding()
                                        {
                                            FindingReason =
                                                "This registry key was found to match a known-vulnerable value.",
                                            FindingDetail = ruleKey.FriendlyDescription + " " + ruleKey.MsDesc,
                                            Triage = ruleKey.Triage
                                        });
                                    }
                                }
                                break;
                            case InterestingIf.NotDefault:
                                if (regValue.ValueName.IndexOf(ruleKey.ValueName, StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    bool interesting = false;
                                    switch (ruleKey.ValueType)
                                    {
                                        case RegKeyValType.REG_DWORD:
                                            int dword;
                                            Int32.TryParse(Encoding.UTF8.GetString(regValue.ValueBytes, 0,
                                                regValue.ValueBytes.Length), out dword);
                                            interesting = IsInterestingBecauseNotDefault(ruleKey.DefaultDword, dword);
                                            break;
                                        case RegKeyValType.REG_BINARY:
                                            interesting = IsInterestingBecauseNotDefault(ruleKey.DefaultBinary,
                                                regValue.ValueBytes);
                                            break;
                                        case RegKeyValType.REG_SZ:
                                            interesting = IsInterestingBecauseNotDefault(ruleKey.DefaultSz, regValue.ValueString);
                                            break;
                                        default:
                                            throw new NotImplementedException("No code to handle rules around " +
                                                                              ruleKey.ValueType.ToString() + " keys.");
                                    }
                                    if (interesting)
                                    {
                                        findings.Add(new GpoFinding()
                                        {
                                            FindingReason = "This registry key was set to a non-default value, which was interesting enough for me.",
                                            FindingDetail = ruleKey.FriendlyDescription + " " + ruleKey.MsDesc,
                                            Triage = ruleKey.Triage
                                        });
                                    }
                                }
                                break;
                            case InterestingIf.NotGood:
                                if (regValue.ValueName.IndexOf(ruleKey.ValueName, StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    bool interesting = false;
                                    switch (ruleKey.ValueType)
                                    {
                                        case RegKeyValType.REG_DWORD:
                                            int dword;
                                            Int32.TryParse(Encoding.UTF8.GetString(regValue.ValueBytes, 0,
                                                regValue.ValueBytes.Length), out dword); interesting = IsInterestingBecauseNotDefault(ruleKey.GoodDword, dword);
                                            break;
                                        case RegKeyValType.REG_BINARY:
                                            interesting = IsInterestingBecauseNotDefault(ruleKey.GoodBinary,
                                                regValue.ValueBytes);
                                            break;
                                        case RegKeyValType.REG_SZ:
                                            interesting = IsInterestingBecauseNotDefault(ruleKey.GoodSz, regValue.ValueString);
                                            break;
                                        default:
                                            throw new NotImplementedException("No code to handle rules around " +
                                                                              ruleKey.ValueType.ToString() + " keys.");
                                    }
                                    if (interesting)
                                    {
                                        findings.Add(new GpoFinding()
                                        {
                                            FindingReason = "This registry key was set to a non-default value, which was interesting enough for me.",
                                            FindingDetail = ruleKey.FriendlyDescription + " " + ruleKey.MsDesc,
                                            Triage = ruleKey.Triage
                                        });
                                    }
                                }
                                break;
                        }
                    }
                }
            }

            // put findings in settingResult
            SettingResult.Findings = findings;

            // make a new setting object minus the ugly bits we don't care about.
            SettingResult.Setting = CleanupSetting(setting);

            return SettingResult;
        }


        public RegistrySetting CleanupSetting(RegistrySetting setting)
        {
            RegistrySetting cleanSetting = new RegistrySetting();

            cleanSetting.PolicyType = setting.PolicyType;

            if (!String.IsNullOrWhiteSpace(setting.Name))
            {
                cleanSetting.Name = setting.Name;
            }

            if (!String.IsNullOrWhiteSpace(setting.Status))
            {
                cleanSetting.Status = setting.Status;
            }

            cleanSetting.Action = setting.Action;
            cleanSetting.Hive = setting.Hive;
            cleanSetting.Key = setting.Key;

            if (setting.ParsedKeySddl != null)
            {
                cleanSetting.ParsedKeySddl = setting.ParsedKeySddl;
            }

            if (!String.IsNullOrWhiteSpace(setting.Inheritance))
            {
                cleanSetting.Inheritance = setting.Inheritance;
            }

            if (setting.Values.Count > 0)
            {
                List<RegistryValue> cleanValues = new List<RegistryValue>();
                foreach (RegistryValue regValue in setting.Values)
                {
                    RegistryValue cleanValue = new RegistryValue();
                    if (!String.IsNullOrWhiteSpace(regValue.ValueName))
                    {
                        cleanValue.ValueName = regValue.ValueName;
                    }
                    cleanValue.RegKeyValType = regValue.RegKeyValType;
                    if (!String.IsNullOrWhiteSpace(regValue.ValueString))
                    {
                        cleanValue.ValueString = regValue.ValueString;
                    }
                    if (cleanValue.ValueName != null)
                    {
                        cleanValues.Add(cleanValue);
                    }
                }
                if (cleanValues.Count > 0)
                {
                    cleanSetting.Values = cleanValues;
                }
            }

            return cleanSetting;
        }


        private bool IsInterestingBecauseNotDefault(int defaultVal, int settingVal)
        {
            if (defaultVal != settingVal)
            {
                return true;
            }
            return false;
        }
        private bool IsInterestingBecauseNotDefault(string defaultVal, string settingVal)
        {
            if (defaultVal != settingVal)
            {
                return true;
            }
            return false;
        }
        private bool IsInterestingBecauseNotDefault(byte[] defaultVal, byte[] settingVal)
        {
            if (defaultVal != settingVal)
            {
                return true;
            }
            return false;
        }
        private bool IsInterestingBecauseNotGood(int goodVal, int settingVal)
        {
            if (goodVal != settingVal)
            {
                return true;
            }
            return false;
        }
        private bool IsInterestingBecauseNotGood(string goodVal, string settingVal)
        {
            if (goodVal != settingVal)
            {
                return true;
            }
            return false;
        }
        private bool IsInterestingBecauseNotGood(byte[] goodVal, byte[] settingVal)
        {
            if (goodVal != settingVal)
            {
                return true;
            }
            return false;
        }
        private bool IsInterestingBecauseBad(int badVal, int settingVal)
        {
            if (badVal == settingVal)
            {
                return true;
            }
            return false;
        }

        private bool IsInterestingBecauseBad(string badVal, string settingVal)
        {
            if (badVal == settingVal)
            {
                return true;
            }
            return false;
        }

        private bool IsInterestingBecauseBad(byte[] badVal, byte[] settingVal)
        {
            if (badVal == settingVal)
            {
                return true;
            }
            return false;
        }
    }
    
}