using LibSnaffle.Concurrency;
using LibSnaffle.Errors;
using Sddl.Parser;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace LibSnaffle.ActiveDirectory
{
    /// <summary>
    /// Represents an .inf file found within a GPO directory.
    /// </summary>
    public class InfGpoFile : GpoFile
    {
        public InfGpoFile(string filepath, FileInfo info, BlockingMq logger) : base(filepath, info, logger)
        {
        }

        public override void Parse()
        {
            GetSettings();
        }

        private void GetSettings()
        {
            //define what a heading looks like
            Regex headingRegex = new Regex(@"^\[(\w+\s?)+\]$");

            string[] infContentArray = GetContentLines();

            string infContentString = GetContentString(infContentArray);

            if (String.IsNullOrWhiteSpace(infContentString))
            {
                return;
            }

            List<int> headingLines = new List<int>();

            //find all the lines that look like a heading and put the line numbers in an array.
            int i = 0;
            foreach (string infLine in infContentArray)
            {
                System.Text.RegularExpressions.Match headingMatch = headingRegex.Match(infLine);
                if (headingMatch.Success)
                {
                    headingLines.Add(i);
                }
                i++;
            }
            // make a dictionary with K/V = start/end of each section
            // this is extraordinarily janky but it works mostly.
            Dictionary<int, int> sectionSlices = new Dictionary<int, int>();
            int idx = 0;
            while (true)
            {
                try
                {
                    int sectionHeading = headingLines[idx];
                    int sectionFinalLine = (headingLines[(idx + 1)] - 1);
                    sectionSlices.Add(sectionHeading, sectionFinalLine);
                    idx++;
                }
                catch (ArgumentOutOfRangeException)
                {
                    int sectionHeading = headingLines[idx];
                    int sectionFinalLine = infContentArray.Length - 1;
                    sectionSlices.Add(sectionHeading, sectionFinalLine);
                    break;
                }
            }


            // iterate over the identified sections and get the heading and contents of each.
            foreach (KeyValuePair<int, int> sectionSlice in sectionSlices)
            {
                try
                {
                    //get the section heading
                    char[] squareBrackets = { '[', ']' };
                    string sectionSliceKey = infContentArray[sectionSlice.Key];
                    string sectionHeading = sectionSliceKey.Trim(squareBrackets);
                    //get the line where the section content starts by adding one to the heading's line
                    int firstLineOfSection = (sectionSlice.Key + 1);
                    //get the first line of the next section
                    int lastLineOfSection = sectionSlice.Value;
                    //subtract one from the other to get the section length, without the heading.
                    int sectionLength = (lastLineOfSection - firstLineOfSection + 1);
                    //get an array segment with the lines
                    ArraySegment<string> sectionContent =
                        new ArraySegment<string>(infContentArray, firstLineOfSection, sectionLength);

                    //iterate over the lines in the section
                    for (int b = sectionContent.Offset; b < (sectionContent.Offset + sectionContent.Count); b++)
                    {
                        string line = sectionContent.Array[b];
                        if (line.Trim() == "") break;
                        // split the line into the key (before the =) and the values (after it)
                        string lineKey = "";
                        string[] splitLine = null;
                        string[] splitValues = null;
                        string lineValues = null;

                        if (line.Contains('='))
                        {
                            splitLine = line.Split('=');
                            lineKey = (splitLine[0]).Trim();
                            lineKey = lineKey.Trim('\\', '"');
                            // then get the values
                            lineValues = (splitLine[1]).Trim();
                            // and split them into an array on ","
                            splitValues = lineValues.Split(',');
                        }
                        else
                        {
                            splitLine = line.Split(',');
                            lineKey = (splitLine[0]).Trim();
                        }

                        switch (sectionHeading)
                        {
                            case "Privilege Rights":
                                PrivRightSetting privRightSetting = new PrivRightSetting
                                {
                                    Source = FilePath,
                                    Privilege = lineKey
                                };
                                foreach (string trusteeSid in splitValues)
                                {
                                    if (String.IsNullOrWhiteSpace(trusteeSid))
                                    {
                                        continue;
                                    }
                                    string sidString = trusteeSid.Trim('*');
                                    if (sidString.StartsWith("S-"))
                                    {
                                        privRightSetting.Trustees.Add(new Trustee(sidString, true));
                                    }
                                    else
                                    {
                                        privRightSetting.Trustees.Add(new Trustee(sidString, false));
                                    }
                                }

                                if (privRightSetting.Trustees.Count >= 1)
                                {
                                    Settings.Add(privRightSetting);
                                }
                                break;
                            case "Registry Values":
                                RegistrySetting regValSetting = new RegistrySetting
                                {
                                    Source = FilePath
                                };
                                // turn the key into properties on the setting obj
                                string[] regPathArray = lineKey.Split('\\');
                                // get the hive
                                regValSetting.RegHiveFromString(regPathArray[0]);
                                // get the key
                                string[] keyArray = regPathArray.Skip(1).Take(regPathArray.Length - 2).ToArray();
                                regValSetting.Key = String.Join("\\", keyArray);

                                // figure out the value type
                                int valType;
                                if (int.TryParse(splitValues[0], out valType))
                                {
                                    // create value objects for each of them
                                    foreach (string value in splitValues.Skip(1))
                                    {
                                        RegistryValue regVal = new RegistryValue
                                        {
                                            ValueName = regPathArray[regPathArray.Length - 1]
                                        };
                                        regVal.RegKeyValType = (RegKeyValType)valType;
                                        regVal.ValueBytes = Encoding.Unicode.GetBytes(value);
                                        regVal.ValueString = value;
                                        // add them to the setting
                                        regValSetting.Values.Add(regVal);
                                    }
                                }

                                // add the setting into settings
                                Settings.Add(regValSetting);
                                break;
                            case "Registry Keys":
                                RegistrySetting regKeySetting = new RegistrySetting
                                {
                                    Source = FilePath
                                };
                                string[] regKeyArray = lineKey.Split('\\');
                                // get the hive
                                regKeySetting.RegHiveFromString(regKeyArray[0].Trim('"'));
                                // get the key
                                regKeySetting.Key = (String.Join("\\", regKeyArray.Skip(1)).Trim('"'));
                                regKeySetting.Inheritance = splitLine[1];
                                if (!String.IsNullOrWhiteSpace(splitLine[2].Trim('"')))
                                {
                                    regKeySetting.KeySddlString = splitLine[2].Trim('"');
                                    // these don't have values, they're just changing acls on keys.
                                    regKeySetting.ParsedKeySddl = new Sddl.Parser.Sddl(regKeySetting.KeySddlString,
                                        SecurableObjectType.RegistryKey);
                                }

                                Settings.Add(regKeySetting);
                                break;
                            case "Kerberos Policy":
                                KerbPolicySetting kerbpolSetting = new KerbPolicySetting
                                {
                                    Source = FilePath,
                                    Key = splitLine[0].Trim(),
                                    Value = splitLine[1].Trim()
                                };
                                Settings.Add(kerbpolSetting);
                                break;
                            case "Event Audit":
                                EventAuditSetting eventAuditSetting = new EventAuditSetting
                                {
                                    Source = FilePath,
                                    AuditType = lineKey
                                };
                                int auditLevel;
                                if (int.TryParse(lineValues[0].ToString(), out auditLevel))
                                {
                                    eventAuditSetting.AuditLevel = auditLevel;
                                }
                                break;
                            case "File Security ":
                                FileSecuritySetting fileSecSetting = new FileSecuritySetting
                                {
                                    Source = FilePath,
                                    FileSecPath = splitLine[0].Trim(),
                                    Sddl = splitLine[1].Trim()
                                };
                                fileSecSetting.ParsedSddl = new Sddl.Parser.Sddl(fileSecSetting.Sddl,
                                        SecurableObjectType.File);
                                Settings.Add(fileSecSetting);
                                break;
                            case "Group Membership":
                                if (lineKey.EndsWith("Memberof"))
                                {
                                    string member = lineKey.Split('_')[0].Trim('*');
                                    string[] groups = splitValues;

                                    // set up the sole member that is gonna go in all of the groupsettings
                                    GroupSettingMember groupSettingMember = new GroupSettingMember();
                                    if (member.StartsWith("S-"))
                                    {
                                        groupSettingMember.Sid = member;
                                        try
                                        {
                                            Trustee trustee = new Trustee(member);
                                            groupSettingMember.Name = trustee.DisplayName;
                                        }
                                        catch (UserException e)
                                        {
                                            groupSettingMember.Name = "SID Resolution Failed";
                                        }
                                    }
                                    else
                                    {
                                        groupSettingMember.Name = member;
                                    }

                                    foreach (string group in groups)
                                    {
                                        if (group == "")
                                        {
                                            continue;
                                        }
                                        else
                                        {
                                            string groupDisplayName;
                                            try
                                            {
                                                if (group.StartsWith("S-"))
                                                {
                                                    Trustee trustee = new Trustee(group.Trim('*'), true);
                                                    groupDisplayName = trustee.DisplayName;
                                                }
                                                else
                                                {
                                                    Trustee trustee = new Trustee(group.Trim('*'), false);
                                                    groupDisplayName = trustee.DisplayName;
                                                }
                                            }
                                            catch (UserException e)
                                            {
                                                Trustee trustee = new Trustee(group.Trim('*'), false);
                                                groupDisplayName = group.Trim('*');
                                            }

                                            GroupSetting groupSetting = new GroupSetting()
                                            { Action = SettingAction.Update };
                                            groupSetting.Name = groupDisplayName;
                                            groupSetting.Source = FilePath;
                                            groupSetting.Members.Add(groupSettingMember);
                                            Settings.Add(groupSetting);
                                        }
                                    }
                                }
                                else if (lineKey.EndsWith("Members"))
                                {
                                    string group = lineKey.Split('_')[0].Trim('*');
                                    string[] members = splitValues;

                                    GroupSetting groupSetting = new GroupSetting() { Action = SettingAction.Update };

                                    if (group.StartsWith("S-"))
                                    {
                                        try
                                        {
                                            Trustee trustee = new Trustee(group);
                                            groupSetting.Name = trustee.DisplayName;
                                        }
                                        catch (UserException e)
                                        {
                                            groupSetting.Name = group;
                                        }
                                    }
                                    else
                                    {
                                        groupSetting.Name = group;
                                    }

                                    foreach (string member in members)
                                    {
                                        if (member == "")
                                        {
                                            continue;
                                        }

                                        GroupSettingMember groupSettingMember = new GroupSettingMember();
                                        string trimmedMember = member.Trim('*');
                                        if (trimmedMember.StartsWith("S-"))
                                        {
                                            groupSettingMember.Sid = trimmedMember;
                                            try
                                            {
                                                Trustee trustee = new Trustee(trimmedMember);
                                                groupSettingMember.Name = trustee.DisplayName;
                                            }
                                            catch (UserException e)
                                            {
                                                groupSettingMember.Name = "SID Resolution Failed";
                                            }
                                        }
                                        else
                                        {
                                            groupSettingMember.Name = trimmedMember;
                                        }

                                        groupSetting.Members.Add(groupSettingMember);
                                    }

                                    if (groupSetting.Members.Count >= 1)
                                    {
                                        groupSetting.Source = FilePath;
                                        Settings.Add(groupSetting);
                                    }
                                }
                                else
                                {
                                    Logger.Error("Unexpected result in Group Membership in inf file " + FilePath);
                                }

                                break;
                            case "Service General Setting":
                                NtServiceSetting serviceSetting = new NtServiceSetting
                                {
                                    Source = FilePath,
                                    ServiceName = lineKey,
                                    StartupType = splitLine[1]
                                };
                                if (!String.IsNullOrWhiteSpace(splitLine[2].Trim('"')))
                                {
                                    serviceSetting.Sddl = splitLine[2].Trim('"');
                                    // these don't have values, they're just changing acls on keys.
                                    serviceSetting.ParsedSddl = new Sddl.Parser.Sddl(serviceSetting.Sddl,
                                        SecurableObjectType.WindowsService);
                                }

                                Settings.Add(serviceSetting);
                                break;
                            case "System Access":
                                SystemAccessSetting sysAccSetting = new SystemAccessSetting
                                {
                                    Source = FilePath,
                                    SettingName = lineKey,
                                    ValueString = splitLine[1].Trim()
                                };
                                Settings.Add(sysAccSetting);
                                break;
                            case "Unicode":
                                // don't care about this but it's expected
                                break;
                            case "Version":
                                // don't care about this but it's expected
                                break;
                            // case "System Log":
                            //     // don't care about this but it's expected
                            //     break;
                            // case "Application Log":
                            //     // don't care about this but it's expected
                            //     break;
                            // case "Security Log":
                            //     // don't care about this but it's expected
                            //     break;
                            // case "Profile Description":
                            //     // don't care about this but it's expected
                            //     break;
                            default:
                                Logger.Degub("Something unexpected or unhandled in an Inf file: " + sectionHeading);
                                break;
                        }

                        if (lineKey == "")
                        {
                            Logger.Error("Something has gone wrong parsing .inf file " + FilePath);
                        }
                    }
                }
                catch
                {
                    Logger.Error("Something has gone wrong parsing " + FilePath);
                }
            }
        }
    }
}
