using ConsoleTables;
using Group3r.Assessment;
using Group3r.Options;
using LibSnaffle.ActiveDirectory;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml;

namespace Group3r.View
{
    /**
     * Summary: Implementation of IGpoOutputter which just returns nice GPO output.
     */
    class NiceGpoPrinter : IGpoPrinter
    {
        private GrouperOptions grouperOptions;
        private int _indent = 4;
        /**
         * Summary: constructor
         * Arguments: none
         * Returns: NiceGpoPrinter instance
         */
        public NiceGpoPrinter(GrouperOptions options)
        {
            this.grouperOptions = options;
            // set up the printer
        }

        /**
         * Summary: Implementation of OutputGPO which returns the GPO as a nice string.
         * Arguments: GPO object to be outputted
         * Returns: string representation of GPO
         */
        public string OutputGPO(GPO gpo)
        {
            string gpoString = "";
            return gpoString;
        }

        public string OutputGpoResult(GpoResult gpoResult)
        {
            if (grouperOptions.CurrentPolOnly && gpoResult.Attributes.IsMorphedGPO)
            {
                return "";
            }
            // bail out entirely if both pol types are disabled and we are running with the -e flag.
            if (grouperOptions.EnabledPolOnly == true)
            {
                if (!gpoResult.Attributes.ComputerPolicyEnabled && !gpoResult.Attributes.UserPolicyEnabled)
                {
                    return "";
                }
            }

            /*
             * GPO NAME AND ATTRIBUTES
             */

            StringBuilder sb = new StringBuilder();
            sb.AppendLine();
            string morphed = "Current";
            if (gpoResult.Attributes.IsMorphedGPO)
            {
                morphed = "Morphed";
            }
            string gpoDisplayName = gpoResult.Attributes.DisplayName;
            if (string.IsNullOrWhiteSpace(gpoDisplayName))
            {
                gpoDisplayName = "(No Display Name)";
            }
            string columntwo = String.Format("{0} {1} {2}", gpoDisplayName, gpoResult.Attributes.Uid, morphed);
            ConsoleTable gpoTable = new ConsoleTable("GPO", columntwo);
            gpoTable.AddRow("Date Created", gpoResult.Attributes.CreatedDate);
            gpoTable.AddRow("Date Modified", gpoResult.Attributes.ModifiedDate);
            gpoTable.AddRow("Path in SYSVOL", gpoResult.Attributes.PathInSysvol);

            string computerPolicy = "Disabled";
            string userPolicy = "Disabled";
            if (gpoResult.Attributes.ComputerPolicyEnabled)
            {
                computerPolicy = "Enabled";
            }
            if (gpoResult.Attributes.UserPolicyEnabled)
            {
                userPolicy = "Enabled";
            }

            gpoTable.AddRow("Computer Policy", computerPolicy);
            gpoTable.AddRow("User Policy", userPolicy);

            // if there are links, add them
            if (gpoResult.Attributes.GpoLinks.Count >= 1)
            {
                bool linkenabled = false;
                foreach (GPOLink gpoLink in gpoResult.Attributes.GpoLinks)
                {
                    string linkPath = String.Format("{0} ({1})", gpoLink.LinkPath, gpoLink.LinkEnforced);
                    // if at least one link isn't enabled...
                    if (gpoLink.LinkEnforced.Contains("Enabled"))
                    {
                        linkenabled = true;
                    }
                    gpoTable.AddRow("Link", linkPath);
                }
                // and we're only showing enabled policies...
                if (!linkenabled && grouperOptions.EnabledPolOnly)
                {
                    // bail out.
                    return "";
                }
            }
            else
            {
                // if there aren't any, and we're only showing enabled policy, bail out.
                if (grouperOptions.EnabledPolOnly)
                {
                    return "";
                }
            }
            sb.Append(gpoTable.ToMarkDownString());
            /*
            * Findings for GPO Attributes
            */

            //ConsoleTable gpoFindingTable = new ConsoleTable("Finding", "Placeholder");
            //gpoFindingTable.AddRow("This is where", "Findings about GPO ACLs will go.");
            //sb.Append(IndentPara(gpoFindingTable.ToMarkDownString(), 1));
            //sb.AppendLine("Findings for GPO Attributes will go here.");
            /*
            if (gpoResult.GpoAttributeFindings.Count >= 1)
            {
                foreach (GpoFinding finding in gpoResult.GpoAttributeFindings)
                {
                    sb.Append(PrintNiceFinding(finding));
                }
            }
            
            sb.AppendLine("-------------------------------");
            sb.AppendLine("ACL Findings for GPO will go here.");
            if (gpoResult.GpoAclResult.Count >= 1)
            {
                sb.AppendLine(PrintNiceAces(gpoResult.GpoAclResult));
            }
            sb.AppendLine("-------------------------------");
            */
            foreach (SettingResult sr in gpoResult.SettingResults)
            {
                if ((sr.Findings.Count == 0) && grouperOptions.FindingsOnly)
                {
                    continue;
                }

                string settingMorphed = "";
                if (sr.Setting.IsMorphed)
                {
                    if (grouperOptions.CurrentPolOnly)
                    {
                        //bail out because this is a morphed setting.
                        continue;
                    }
                    settingMorphed = " - Morphed";
                }

                string poltype = "";

                if (sr.Setting.PolicyType == PolicyType.Computer)
                {
                    // if computer policy is disabled on this GPO, skip it.
                    if (grouperOptions.EnabledPolOnly && !gpoResult.Attributes.ComputerPolicyEnabled)
                    {
                        continue;
                    }
                    poltype = "Computer Policy" + settingMorphed;
                }
                else if (sr.Setting.PolicyType == PolicyType.User)
                {
                    if (grouperOptions.EnabledPolOnly && !gpoResult.Attributes.UserPolicyEnabled)
                    {
                        continue;
                    }
                    poltype = "User Policy" + settingMorphed;
                }
                else if (sr.Setting.PolicyType == PolicyType.Package)
                {
                    poltype = "Package Policy" + settingMorphed;
                }

                // big ol' list of output formatters that should be their own methods but i'm a MANIAC AND YOU CAN'T STOP ME!
                if (sr.Setting.GetType() == typeof(DataSourceSetting))
                {
                    DataSourceSetting cs = (DataSourceSetting)sr.Setting;

                    ConsoleTable sTable = new ConsoleTable("Setting - " + poltype, "Data Source");

                    sTable = TableAdd(sTable, "Name", cs.Name);
                    sTable = TableAdd(sTable, "Action", cs.Action.ToString());
                    sTable = TableAdd(sTable, "Description", cs.Description);
                    sTable = TableAdd(sTable, "Driver", cs.Driver);
                    sTable = TableAdd(sTable, "UserName", cs.UserName);
                    sTable = TableAdd(sTable, "Cpassword", cs.Cpassword);
                    sTable = TableAdd(sTable, "Password", cs.DSN);

                    sb.Append(IndentPara(sTable.ToMarkDownString(), 1));
                }
                else if (sr.Setting.GetType() == typeof(DeviceSetting))
                {
                    DeviceSetting cs = (DeviceSetting)sr.Setting;

                    ConsoleTable sTable = new ConsoleTable("Setting - " + poltype, "Devices");
                    sTable = TableAdd(sTable, "No Output Formatter For This Setting Type", "");

                    //sTable = TableAdd(sTable, "Action", cs.FileAction);

                    sb.Append(IndentPara(sTable.ToMarkDownString(), 1));
                }
                else if (sr.Setting.GetType() == typeof(DriveSetting))
                {
                    DriveSetting cs = (DriveSetting)sr.Setting;

                    ConsoleTable sTable = new ConsoleTable("Setting - " + poltype, "Drive");

                    sTable = TableAdd(sTable, "Name", cs.Name);
                    sTable = TableAdd(sTable, "Action", cs.Action.ToString());
                    sTable = TableAdd(sTable, "Path", cs.Path);
                    sTable = TableAdd(sTable, "Label", cs.Label);
                    sTable = TableAdd(sTable, "UserName", cs.UserName);
                    sTable = TableAdd(sTable, "Cpassword", cs.Cpassword);
                    sTable = TableAdd(sTable, "Password", cs.Password);

                    sb.Append(IndentPara(sTable.ToMarkDownString(), 1));

                }
                else if (sr.Setting.GetType() == typeof(EnvVarSetting))
                {
                    EnvVarSetting cs = (EnvVarSetting)sr.Setting;

                    ConsoleTable sTable = new ConsoleTable("Setting - " + poltype, "Env Variable");
                    sTable = TableAdd(sTable, "No Output Formatter For This Setting Type", "");

                    //sTable = TableAdd(sTable, "Action", cs.FileAction);

                    sb.Append(IndentPara(sTable.ToMarkDownString(), 1));
                }
                else if (sr.Setting.GetType() == typeof(EventAuditSetting))
                {
                    EventAuditSetting cs = (EventAuditSetting)sr.Setting;

                    ConsoleTable sTable = new ConsoleTable("Setting - " + poltype, "Audit Policy");
                    sTable = TableAdd(sTable, "No Output Formatter For This Setting Type", "");

                    //sTable = TableAdd(sTable, "Action", cs.FileAction);

                    sb.Append(IndentPara(sTable.ToMarkDownString(), 1));
                }
                else if (sr.Setting.GetType() == typeof(FileSetting))
                {
                    FileSetting cs = (FileSetting)sr.Setting;

                    ConsoleTable sTable = new ConsoleTable("Setting - " + poltype, "File");

                    sTable = TableAdd(sTable, "Action", cs.FileAction);
                    sTable = TableAdd(sTable, "FileName", cs.FileName);
                    sTable = TableAdd(sTable, "FromPath", cs.FromPath);
                    sTable = TableAdd(sTable, "TargetPath", cs.TargetPath);

                    sb.Append(IndentPara(sTable.ToMarkDownString(), 1));
                }
                else if (sr.Setting.GetType() == typeof(FolderSetting))
                {
                    FolderSetting cs = (FolderSetting)sr.Setting;

                    ConsoleTable sTable = new ConsoleTable("Setting - " + poltype, "Folder");

                    //sTable = TableAdd(sTable, "Action", cs.FileAction);

                    sb.Append(IndentPara(sTable.ToMarkDownString(), 1));
                }
                else if (sr.Setting.GetType() == typeof(GroupSetting))
                {
                    GroupSetting cs = (GroupSetting)sr.Setting;

                    ConsoleTable sTable = new ConsoleTable("Setting - " + poltype, "Group");

                    sTable = TableAdd(sTable, "Name", cs.Name);
                    sTable = TableAdd(sTable, "Action", cs.Action.ToString());
                    sTable = TableAdd(sTable, "NewName", cs.NewName);
                    sTable = TableAdd(sTable, "Delete All Groups", cs.DeleteAllGroups.ToString());
                    sTable = TableAdd(sTable, "Delete All Users", cs.DeleteAllUsers.ToString());
                    sTable = TableAdd(sTable, "Remove Accounts", cs.RemoveAccounts.ToString());

                    foreach (GroupSettingMember member in cs.Members)
                    {
                        string memberstring = member.Action + " " + member.Name + " " + member.ResolvedName + " " + member.Sid;

                        sTable = TableAdd(sTable, "Member", memberstring);
                    }

                    sb.Append(IndentPara(sTable.ToMarkDownString(), 1));

                }
                else if (sr.Setting.GetType() == typeof(IniFileSetting))
                {
                    IniFileSetting cs = (IniFileSetting)sr.Setting;

                    ConsoleTable sTable = new ConsoleTable("Setting - " + poltype, "Ini File");

                    sTable = TableAdd(sTable, "No Output Formatter For This Setting Type", "");
                    //sTable = TableAdd(sTable, "Action", cs.FileAction);

                    sb.Append(IndentPara(sTable.ToMarkDownString(), 1));
                }
                else if (sr.Setting.GetType() == typeof(KerbPolicySetting))
                {
                    KerbPolicySetting cs = (KerbPolicySetting)sr.Setting;

                    ConsoleTable sTable = new ConsoleTable("Setting - " + poltype, "Kerberos Policy");

                    sTable = TableAdd(sTable, cs.Key, cs.Value);

                    sb.Append(IndentPara(sTable.ToMarkDownString(), 1));
                }
                else if (sr.Setting.GetType() == typeof(NetOptionSetting))
                {
                    NetOptionSetting cs = (NetOptionSetting)sr.Setting;
                    ConsoleTable sTable = new ConsoleTable("Setting - " + poltype, "Network Options");

                    sTable = TableAdd(sTable, "No Output Formatter For This Setting Type", "");

                    //sTable = TableAdd(sTable, "Action", cs.FileAction);

                    sb.Append(IndentPara(sTable.ToMarkDownString(), 1));
                }
                else if (sr.Setting.GetType() == typeof(NetworkShareSetting))
                {
                    NetworkShareSetting cs = (NetworkShareSetting)sr.Setting;
                    ConsoleTable sTable = new ConsoleTable("Setting - " + poltype, "Network Share");

                    sTable = TableAdd(sTable, "No Output Formatter For This Setting Type", "");

                    //sTable = TableAdd(sTable, "Action", cs.FileAction);

                    sb.Append(IndentPara(sTable.ToMarkDownString(), 1));
                }
                else if (sr.Setting.GetType() == typeof(NtServiceSetting))
                {
                    NtServiceSetting cs = (NtServiceSetting)sr.Setting;

                    ConsoleTable sTable = new ConsoleTable("Setting - " + poltype, "Service");

                    sTable = TableAdd(sTable, "Name", cs.Name);
                    sTable = TableAdd(sTable, "Service Name", cs.ServiceName);
                    if (cs.StartupType != null)
                    {
                        string startupType = "";
                        switch (cs.StartupType)
                        {
                            case "0":
                                startupType = "Boot";
                                break;
                            case "1":
                                startupType = "System";
                                break;
                            case "2":
                                startupType = "Automatic";
                                break;
                            case "3":
                                startupType = "Manual";
                                break;
                            case "4":
                                startupType = "Disabled";
                                break;
                        }

                        sTable = TableAdd(sTable, "Startup Type", startupType);
                    }

                    sTable = TableAdd(sTable, "Sddl", cs.Sddl);
                    sTable = TableAdd(sTable, "Program", cs.Program);
                    sTable = TableAdd(sTable, "Args", cs.Args);
                    sTable = TableAdd(sTable, "UserName", cs.UserName);
                    sTable = TableAdd(sTable, "Cpassword", cs.Cpassword);
                    sTable = TableAdd(sTable, "Password", cs.Password);

                    sb.Append(IndentPara(sTable.ToMarkDownString(), 1));
                }
                else if (sr.Setting.GetType() == typeof(PackageSetting))
                {
                    PackageSetting cs = (PackageSetting)sr.Setting;

                    ConsoleTable sTable = new ConsoleTable("Setting - " + poltype, "Package");

                    sTable = TableAdd(sTable, "Display Name", cs.DisplayName);
                    sTable = TableAdd(sTable, "CreatedDate", cs.CreatedDate.ToString());
                    sTable = TableAdd(sTable, "Action", cs.PackageAction);

                    foreach (string file in cs.MsiFileList)
                    {
                        sTable = TableAdd(sTable, "File", file);
                    }
                    sTable = TableAdd(sTable, "Product Code", cs.ProductCode.ToString());
                    sTable = TableAdd(sTable, "Upgrade Product Code", cs.UpgradeProductCode.ToString());

                    sb.Append(IndentPara(sTable.ToMarkDownString(), 1));
                }
                else if (sr.Setting.GetType() == typeof(PrinterSetting))
                {
                    PrinterSetting cs = (PrinterSetting)sr.Setting;

                    ConsoleTable sTable = new ConsoleTable("Setting - " + poltype, "Printer");

                    sTable = TableAdd(sTable, "Name", cs.Name);
                    sTable = TableAdd(sTable, "Action", cs.Action.ToString());
                    sTable = TableAdd(sTable, "Comment", cs.Comment);
                    sTable = TableAdd(sTable, "Path", cs.Path);
                    sTable = TableAdd(sTable, "UserName", cs.UserName);
                    sTable = TableAdd(sTable, "Cpassword", cs.Cpassword);
                    sTable = TableAdd(sTable, "Password", cs.Password);

                    sb.Append(IndentPara(sTable.ToMarkDownString(), 1));
                }
                else if (sr.Setting.GetType() == typeof(PrivRightSetting))
                {
                    PrivRightSetting cs = (PrivRightSetting)sr.Setting;

                    ConsoleTable sTable = new ConsoleTable("Setting - " + poltype, "User Rights Assignment");

                    sTable = TableAdd(sTable, "Privilege Name", cs.Privilege);

                    bool first = true;
                    string t = "Trustee";
                    foreach (Trustee trustee in cs.Trustees)
                    {
                        if (first)
                        {
                            first = false;
                        }
                        else
                        {
                            t = "";
                        }
                        if (trustee.DisplayName == "Failed to resolve SID.")
                        {
                            sTable = TableAdd(sTable, t, trustee.Sid);
                        }
                        else
                        {
                            sTable = TableAdd(sTable, t, trustee.DisplayName + " " + trustee.Sid);
                        }
                    }
                    sb.Append(IndentPara(sTable.ToMarkDownString(), 1));
                }
                else if (sr.Setting.GetType() == typeof(RegistrySetting))
                {
                    RegistrySetting cs = (RegistrySetting)sr.Setting;

                    ConsoleTable sTable = new ConsoleTable("Setting - " + poltype, "Registry");

                    sTable = TableAdd(sTable, "Name", cs.Name);
                    sTable = TableAdd(sTable, "Action", cs.Action.ToString());
                    sTable = TableAdd(sTable, "Key", cs.Hive.ToString() + cs.Key);

                    foreach (RegistryValue value in cs.Values)
                    {
                        sTable = TableAdd(sTable, "Value Name", value.ValueName);
                        sTable = TableAdd(sTable, "Value Type", value.RegKeyValType.ToString());
                        sTable = TableAdd(sTable, "Value String", value.ValueString);
                    }

                    Console.WriteLine(sTable.ToMarkDownString());
                    sb.Append(IndentPara(sTable.ToMarkDownString(), 1));
                }
                else if (sr.Setting.GetType() == typeof(SchedTaskSetting))
                {
                    SchedTaskSetting cs = (SchedTaskSetting)sr.Setting;

                    ConsoleTable sTable = new ConsoleTable("Setting - " + poltype, "Scheduled Task");

                    sTable = TableAdd(sTable, "Name", cs.Name);
                    sTable = TableAdd(sTable, "Task Type", cs.TaskType.ToString());
                    sTable = TableAdd(sTable, "Description", cs.Description1);
                    sTable = TableAdd(sTable, "Enabled", cs.Enabled.ToString());
                    sTable = TableAdd(sTable, "Name", cs.Name);

                    sb.Append(IndentPara(sTable.ToMarkDownString(), 1));

                    if (cs.Principals.Count >= 1)
                    {
                        int i = 1;
                        foreach (SchedTaskPrincipal principal in cs.Principals)
                        {
                            ConsoleTable pTable = new ConsoleTable("Principal", i.ToString());
                            pTable = TableAdd(pTable, "Id", principal.Id);
                            pTable = TableAdd(pTable, "UserID", principal.UserId);
                            pTable = TableAdd(pTable, "Cpassword", principal.Cpassword);
                            pTable = TableAdd(pTable, "Password", principal.Password);
                            pTable = TableAdd(pTable, "LogonType", principal.LogonType);
                            pTable = TableAdd(pTable, "RunLevel", principal.RunLevel);
                            sb.Append(IndentPara(pTable.ToMarkDownString(), 2));
                            i++;
                        }
                    }

                    if (cs.Actions.Count >= 1)
                    {
                        foreach (SchedTaskAction action in cs.Actions)
                        {
                            if (action.GetType() == typeof(SchedTaskEmailAction))
                            {
                                SchedTaskEmailAction ca = (SchedTaskEmailAction)action;

                                ConsoleTable aTable = new ConsoleTable("Email Action", "");
                                aTable = TableAdd(aTable, "From", ca.From);
                                aTable = TableAdd(aTable, "To", ca.To);
                                aTable = TableAdd(aTable, "Subject", ca.Subject);
                                aTable = TableAdd(aTable, "Body", ca.Body);
                                aTable = TableAdd(aTable, "Header Fields", ca.HeaderFields);
                                aTable = TableAdd(aTable, "Server", ca.Server);
                                if (ca.Attachments.Count >= 1)
                                {
                                    foreach (string attachment in ca.Attachments)
                                    {
                                        aTable = TableAdd(aTable, "Attachment", attachment);
                                    }
                                }
                                sb.Append(IndentPara(aTable.ToMarkDownString(), 2));
                            }
                            else if (action.GetType() == typeof(SchedTaskExecAction))
                            {
                                SchedTaskExecAction ca = (SchedTaskExecAction)action;

                                ConsoleTable aTable = new ConsoleTable("Execute Action", "");
                                sTable = TableAdd(aTable, "Command", ca.Command);
                                sTable = TableAdd(aTable, "Args", ca.Args);
                                sTable = TableAdd(aTable, "Working Directory", ca.WorkingDir);

                                sb.Append(IndentPara(aTable.ToMarkDownString(), 2));
                            }
                            else if (action.GetType() == typeof(SchedTaskShowMessageAction))
                            {
                                SchedTaskShowMessageAction ca = (SchedTaskShowMessageAction)action;

                                ConsoleTable aTable = new ConsoleTable("Message Action", "");

                                sTable = TableAdd(aTable, "Title", ca.Title);
                                sTable = TableAdd(aTable, "Body", ca.Body);
                                sb.Append(IndentPara(aTable.ToMarkDownString(), 2));
                            }
                        }
                    }

                    if (cs.Triggers.Count >= 1)
                    {
                        ConsoleTable tTable = new ConsoleTable("Triggers", "");
                        foreach (XmlNode node in cs.Triggers)
                        {
                            tTable = TableAdd(tTable, "", node.InnerXml);
                        }

                        sb.Append(IndentPara(tTable.ToMarkDownString(), 2));
                    }
                }
                else if (sr.Setting.GetType() == typeof(ScriptSetting))
                {
                    ScriptSetting cs = (ScriptSetting)sr.Setting;

                    ConsoleTable sTable = new ConsoleTable("Setting - " + poltype, "Script");

                    sTable = TableAdd(sTable, "Script Type", cs.ScriptType.ToString());
                    sTable = TableAdd(sTable, "CmdLine", cs.CmdLine);
                    sTable = TableAdd(sTable, "Args", cs.Parameters);

                    sb.Append(IndentPara(sTable.ToMarkDownString(), 1));
                }
                else if (sr.Setting.GetType() == typeof(ShortcutSetting))
                {
                    ShortcutSetting cs = (ShortcutSetting)sr.Setting;

                    ConsoleTable sTable = new ConsoleTable("Setting - " + poltype, "Shortcut");

                    sTable = TableAdd(sTable, "Name", cs.Name);
                    sTable = TableAdd(sTable, "Action", cs.Action.ToString());
                    sTable = TableAdd(sTable, "Comment", cs.Comment);
                    sTable = TableAdd(sTable, "Shortcut Path", cs.ShortcutPath);
                    sTable = TableAdd(sTable, "Target Type", cs.TargetType);
                    sTable = TableAdd(sTable, "Target Path", cs.TargetPath);
                    sTable = TableAdd(sTable, "Arguments", cs.Arguments);
                    sTable = TableAdd(sTable, "IconPath", cs.IconPath);
                    sTable = TableAdd(sTable, "IconIndex", cs.IconIndex);
                    sTable = TableAdd(sTable, "Status", cs.Status);

                    sb.Append(IndentPara(sTable.ToMarkDownString(), 1));
                }
                else if (sr.Setting.GetType() == typeof(SystemAccessSetting))
                {
                    SystemAccessSetting cs = (SystemAccessSetting)sr.Setting;

                    ConsoleTable sTable = new ConsoleTable("Setting - " + poltype, "System Access");
                    sTable = TableAdd(sTable, cs.SettingName, cs.ValueString);
                    sb.Append(IndentPara(sTable.ToMarkDownString(), 1));

                }
                else if (sr.Setting.GetType() == typeof(UserSetting))
                {
                    UserSetting cs = (UserSetting)sr.Setting;

                    ConsoleTable sTable = new ConsoleTable("Setting - " + poltype, "User");

                    sTable = TableAdd(sTable, "Name", cs.Name);
                    sTable = TableAdd(sTable, "Action", cs.Action.ToString());
                    sTable = TableAdd(sTable, "UserName", cs.UserName);
                    sTable = TableAdd(sTable, "NewName", cs.NewName);
                    sTable = TableAdd(sTable, "FullName", cs.FullName);
                    sTable = TableAdd(sTable, "Description", cs.Description);
                    sTable = TableAdd(sTable, "Cpassword", cs.Cpassword);
                    sTable = TableAdd(sTable, "Password", cs.Password);
                    sTable = TableAdd(sTable, "PwNeverExpires", cs.PwNeverExpires.ToString());

                    sb.Append(IndentPara(sTable.ToMarkDownString(), 1));
                }
                else
                {
                    throw new NotImplementedException("Trying to output a setting type with no output formatter: " + sr.Setting.GetType().ToString());
                }

                if (sr.Findings.Count >= 1)
                {
                    foreach (GpoFinding finding in sr.Findings)
                    {
                        sb.Append(PrintNiceFinding(finding));
                    }
                }

                sb.AppendLine();
            }
            return sb.ToString();
        }
        string PrintNiceFinding(GpoFinding finding)
        {
            StringBuilder sb = new StringBuilder();

            ConsoleTable fTable = new ConsoleTable("Finding", finding.Triage.ToString());

            fTable = TableAdd(fTable, "Reason", finding.FindingReason);
            fTable = TableAdd(fTable, "Detail", finding.FindingDetail);

            sb.Append(IndentPara(fTable.ToMarkDownString(), 2));

            /*
            if (finding.AclResult.Count >= 1)
            {
                sb.AppendLine("...ACL.Finding.Details...");
                sb.AppendLine(PrintNiceAces(finding.AclResult));
                sb.AppendLine("......");
            }
            */

            /*
            if (finding.PathFindings.Count >= 1)
            {
                sb.AppendLine("...Path.Finding.Details...");
                sb.AppendLine(PrintNicePathFindings(finding.PathFindings));
                sb.AppendLine("......");
            }
            */

            return sb.ToString();
        }

        static IEnumerable<string> ChunksUpto(string str, int maxChunkSize)
        {
            for (int i = 0; i < str.Length; i += maxChunkSize)
                yield return str.Substring(i, Math.Min(maxChunkSize, str.Length - i));
        }

        ConsoleTable TableAdd(ConsoleTable table, string v1, string v2)
        {
            if (String.IsNullOrWhiteSpace(v2))
            {
                return table;
            }
            if (v2.Length > 80)
            {
                string wrapped = WordWrap(v2, 80);
                IEnumerable<String> strchunks = wrapped.Split('\n');
                //IEnumerable<String> strchunks = ChunksUpto(v2, 80);

                bool first = true;
                foreach (string chunk in strchunks)
                {
                    if (first)
                    {
                        table.AddRow(v1, chunk.Trim());
                        first = false;
                    }
                    else
                    {
                        table.AddRow("", chunk.Trim());
                    }
                }
            }
            else
            {
                table.AddRow(v1, v2);
            }

            return table;
        }

        static char[] splitChars = new char[] { ' ', '-', '\t' };

        private static string WordWrap(string str, int width)
        {
            string[] words = Explode(str, splitChars);

            int curLineLength = 0;
            StringBuilder strBuilder = new StringBuilder();
            for (int i = 0; i < words.Length; i += 1)
            {
                string word = words[i];
                // If adding the new word to the current line would be too long,
                // then put it on a new line (and split it up if it's too long).
                if (curLineLength + word.Length > width)
                {
                    // Only move down to a new line if we have text on the current line.
                    // Avoids situation where wrapped whitespace causes emptylines in text.
                    if (curLineLength > 0)
                    {
                        strBuilder.Append(Environment.NewLine);
                        curLineLength = 0;
                    }

                    // If the current word is too long to fit on a line even on it's own then
                    // split the word up.
                    while (word.Length > width)
                    {
                        strBuilder.Append(word.Substring(0, width - 1) + "-");
                        word = word.Substring(width - 1);

                        strBuilder.Append(Environment.NewLine);
                    }

                    // Remove leading whitespace from the word so the new line starts flush to the left.
                    word = word.TrimStart();
                }
                strBuilder.Append(word);
                curLineLength += word.Length;
            }

            return strBuilder.ToString();
        }

        private static string[] Explode(string str, char[] splitChars)
        {
            List<string> parts = new List<string>();
            int startIndex = 0;
            while (true)
            {
                int index = str.IndexOfAny(splitChars, startIndex);

                if (index == -1)
                {
                    parts.Add(str.Substring(startIndex));
                    return parts.ToArray();
                }

                string word = str.Substring(startIndex, index - startIndex);
                char nextChar = str.Substring(index, 1)[0];
                // Dashes and the likes should stick to the word occuring before it. Whitespace doesn't have to.
                if (char.IsWhiteSpace(nextChar))
                {
                    parts.Add(word);
                    parts.Add(nextChar.ToString());
                }
                else
                {
                    parts.Add(word + nextChar);
                }

                startIndex = index + 1;
            }
        }

        string PrintNiceAces(List<SimpleAce> aces)
        {
            StringBuilder sb = new StringBuilder();

            foreach (SimpleAce ace in aces)
            {
                sb.AppendLine("COMING SOON - ACLS!");
            }
            return sb.ToString();
        }

        string IndentPara(string inString, int indentfactor, bool tailOn = true)
        {
            string istring = String.Concat(Enumerable.Repeat(" ", _indent));
            string fullindent = String.Concat(Enumerable.Repeat(istring, indentfactor));
            string tailend = String.Concat(Enumerable.Repeat("_", (_indent - 1)));
            string tail = "\\" + tailend;
            StringBuilder sb = new StringBuilder();
            string taildent = String.Concat(Enumerable.Repeat(istring, indentfactor - 1));
            if (tailOn)
            {
                sb.Append(taildent + tail + "\r\n" + fullindent);
            }
            sb.Append(inString.Replace("\r\n", "\r\n" + fullindent));
             return (sb.ToString().TrimEnd() + "\r\n");
        }
    }
}
