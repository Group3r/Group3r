using System;
using System.Collections.Generic;
using System.Linq;
using Group3r.Assessment;
using LibSnaffle.ActiveDirectory;
using System.Text;
using System.Xml;
using Group3r.Options;
using ConsoleTables;

namespace Group3r.View
{
    /**
     * Summary: Implementation of IGpoOutputter which just returns nice GPO output.
     */
    class NiceGpoPrinter : IGpoPrinter
    {
        private GrouperOptions grouperOptions;
        private int indent = 4;
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
            ConsoleTable gpoTable = new ConsoleTable("GPO",columntwo);
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
            
            foreach (GPOLink gpoLink in gpoResult.Attributes.GpoLinks)
            {
                string linkPath = String.Format("{0} ({1})", gpoLink.LinkPath, gpoLink.LinkEnforced);
                gpoTable.AddRow("Link", linkPath);
            }
            sb.AppendLine(gpoTable.ToMarkDownString());
            /*
            * Findings for GPO Attributes
            */

            ConsoleTable gpoFindingTable = new ConsoleTable("Finding", "Placeholder");
            gpoFindingTable.AddRow("Placeholder", "Placeholder");
            sb.AppendLine(IndentPara(gpoFindingTable.ToMarkDownString(), 1));
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

                string poltype = "";

                if (sr.Setting.PolicyType == PolicyType.Computer)
                {
                    poltype = "Computer Policy";
                }
                else if (sr.Setting.PolicyType == PolicyType.User)
                {
                    poltype = "User Policy";

                }
/*
                    ConsoleTable sTable = new ConsoleTable(poltype + " | Setting", "Data Source");

                    sTable = TableAdd(sTable, "Name", cs.Name);

                    sb.AppendLine(IndentPara(sTable.ToMarkDownString(), 1));
*/
                if (sr.Setting.GetType() == typeof(DataSourceSetting))
                {
                    DataSourceSetting cs = (DataSourceSetting)sr.Setting;

                    ConsoleTable sTable = new ConsoleTable(poltype + " | Setting", "Data Source");

                    sTable = TableAdd(sTable, "Name", cs.Name);
                    sTable = TableAdd(sTable, "Action", cs.Action.ToString());
                    sTable = TableAdd(sTable, "Description", cs.Description);
                    sTable = TableAdd(sTable, "Driver", cs.Driver);
                    sTable = TableAdd(sTable, "UserName", cs.UserName);
                    sTable = TableAdd(sTable, "Cpassword", cs.Cpassword);
                    sTable = TableAdd(sTable, "Password", cs.DSN);

                    sb.AppendLine(IndentPara(sTable.ToMarkDownString(), 1));
                }
                else if (sr.Setting.GetType() == typeof(DeviceSetting))
                {
                    DeviceSetting cs = (DeviceSetting)sr.Setting;
                }
                else if (sr.Setting.GetType() == typeof(DriveSetting))
                {
                    DriveSetting cs = (DriveSetting)sr.Setting;

                    ConsoleTable sTable = new ConsoleTable(poltype + " | Setting", "Drive");

                    sTable = TableAdd(sTable, "Name", cs.Name);
                    sTable = TableAdd(sTable, "Action", cs.Action.ToString());
                    sTable = TableAdd(sTable, "Path", cs.Path);
                    sTable = TableAdd(sTable, "Label", cs.Label);
                    sTable = TableAdd(sTable, "UserName", cs.UserName);
                    sTable = TableAdd(sTable, "Cpassword", cs.Cpassword);
                    sTable = TableAdd(sTable, "Password", cs.Password);

                    sb.AppendLine(IndentPara(sTable.ToMarkDownString(), 1));

                }
                else if (sr.Setting.GetType() == typeof(EnvVarSetting))
                {
                    EnvVarSetting cs = (EnvVarSetting)sr.Setting;

                }
                else if (sr.Setting.GetType() == typeof(EventAuditSetting))
                {
                    EventAuditSetting cs = (EventAuditSetting)sr.Setting;

                }
                else if (sr.Setting.GetType() == typeof(FileSetting))
                {
                    FileSetting cs = (FileSetting)sr.Setting;

                    ConsoleTable sTable = new ConsoleTable(poltype + " | Setting", "File");

                    sTable = TableAdd(sTable, "Action", cs.FileAction);
                    sTable = TableAdd(sTable, "FileName", cs.FileName);
                    sTable = TableAdd(sTable, "FromPath", cs.FromPath);
                    sTable = TableAdd(sTable, "TargetPath", cs.TargetPath);

                    sb.AppendLine(IndentPara(sTable.ToMarkDownString(), 1));
                }
                else if (sr.Setting.GetType() == typeof(FolderSetting))
                {
                    FolderSetting cs = (FolderSetting)sr.Setting;
                }
                else if (sr.Setting.GetType() == typeof(GroupSetting))
                {
                    GroupSetting cs = (GroupSetting)sr.Setting;

                    ConsoleTable sTable = new ConsoleTable(poltype + " | Setting", "Group");

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

                    sb.AppendLine(IndentPara(sTable.ToMarkDownString(), 1));

                }
                else if (sr.Setting.GetType() == typeof(IniFileSetting))
                {
                    IniFileSetting cs = (IniFileSetting)sr.Setting;

                }
                else if (sr.Setting.GetType() == typeof(KerbPolicySetting))
                {
                    KerbPolicySetting cs = (KerbPolicySetting)sr.Setting;

                }
                else if (sr.Setting.GetType() == typeof(NetOptionSetting))
                {
                    NetOptionSetting cs = (NetOptionSetting)sr.Setting;

                }
                else if (sr.Setting.GetType() == typeof(NetworkShareSetting))
                {
                    NetworkShareSetting cs = (NetworkShareSetting)sr.Setting;

                }
                else if (sr.Setting.GetType() == typeof(NtServiceSetting))
                {
                    NtServiceSetting cs = (NtServiceSetting)sr.Setting;


                    ConsoleTable sTable = new ConsoleTable(poltype + " | Setting", "Service");

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

                    sb.AppendLine(IndentPara(sTable.ToMarkDownString(), 1));
                }
                else if (sr.Setting.GetType() == typeof(PackageSetting))
                {
                    PackageSetting cs = (PackageSetting)sr.Setting;

                    ConsoleTable sTable = new ConsoleTable(poltype + " | Setting", "Package");

                    sTable = TableAdd(sTable, "Display Name", cs.DisplayName);
                    sTable = TableAdd(sTable, "CreatedDate", cs.CreatedDate.ToString());
                    sTable = TableAdd(sTable, "Action", cs.PackageAction);

                    foreach (string file in cs.MsiFileList)
                    {
                        sTable = TableAdd(sTable, "File", file);
                    }
                    sTable = TableAdd(sTable, "Product Code", cs.ProductCode.ToString());
                    sTable = TableAdd(sTable, "Upgrade Product Code", cs.UpgradeProductCode.ToString());

                    sb.AppendLine(IndentPara(sTable.ToMarkDownString(), 1));
                }
                else if (sr.Setting.GetType() == typeof(PrinterSetting))
                {
                    PrinterSetting cs = (PrinterSetting)sr.Setting;

                    ConsoleTable sTable = new ConsoleTable(poltype + " | Setting", "Printer");

                    sTable = TableAdd(sTable, "Name", cs.Name);
                    sTable = TableAdd(sTable, "Action", cs.Action.ToString());
                    sTable = TableAdd(sTable, "Comment", cs.Comment);
                    sTable = TableAdd(sTable, "Path", cs.Path);
                    sTable = TableAdd(sTable, "UserName", cs.UserName);
                    sTable = TableAdd(sTable, "Cpassword", cs.Cpassword);
                    sTable = TableAdd(sTable, "Password", cs.Password);

                    sb.AppendLine(IndentPara(sTable.ToMarkDownString(), 1));
                }
                else if (sr.Setting.GetType() == typeof(PrivRightSetting))
                {
                    PrivRightSetting cs = (PrivRightSetting)sr.Setting;

                    ConsoleTable sTable = new ConsoleTable(poltype + " | Setting", "User Rights Assignment");

                    sTable = TableAdd(sTable, " Privilege Name", cs.Privilege);

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
                    sb.AppendLine(IndentPara(sTable.ToMarkDownString(), 1));
                }
                else if (sr.Setting.GetType() == typeof(RegistrySetting))
                {
                    RegistrySetting cs = (RegistrySetting)sr.Setting;

                    ConsoleTable sTable = new ConsoleTable(poltype + " | Setting", "Registry");

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
                    sb.AppendLine(IndentPara(sTable.ToMarkDownString(), 1));
                }
                else if (sr.Setting.GetType() == typeof(SchedTaskSetting))
                {
                    SchedTaskSetting cs = (SchedTaskSetting)sr.Setting;

                    ConsoleTable sTable = new ConsoleTable(poltype + " | Setting", "Scheduled Task");

                    sTable = TableAdd(sTable, "Name", cs.Name);
                    sTable = TableAdd(sTable, "Task Type", cs.TaskType.ToString());
                    sTable = TableAdd(sTable, "Description", cs.Description1);
                    sTable = TableAdd(sTable, "Enabled", cs.Enabled.ToString());
                    sTable = TableAdd(sTable, "Name", cs.Name);
                    
                    sb.AppendLine(IndentPara(sTable.ToMarkDownString(), 1));

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
                            sb.AppendLine(IndentPara(pTable.ToMarkDownString(), 2));
                            i++;
                        }
                    }

                    if (cs.Actions.Count >= 1)
                    {
                        foreach (SchedTaskAction action in cs.Actions)
                        {
                            if (action.GetType() == typeof(SchedTaskEmailAction))
                            {
                                SchedTaskEmailAction ca = (SchedTaskEmailAction) action;

                                ConsoleTable aTable = new ConsoleTable("Email Action", "");
                                aTable = TableAdd(aTable, "From", ca.From);
                                aTable = TableAdd(aTable, "To", ca.To);
                                aTable = TableAdd(aTable, "Subject", ca.Subject);
                                aTable = TableAdd(aTable, "Body", ca.Body);
                                aTable = TableAdd(aTable, "Server", ca.Server);
                                aTable = TableAdd(aTable, "Header Fields", ca.HeaderFields);
                                aTable = TableAdd(aTable, "Server", ca.Server);
                                if (ca.Attachments.Count >= 1)
                                {
                                    foreach (string attachment in ca.Attachments)
                                    {
                                        aTable = TableAdd(aTable, "Attachment", attachment);
                                    }                                    
                                }
                                sb.AppendLine(IndentPara(aTable.ToMarkDownString(), 2));
                            }
                            else if (action.GetType() == typeof(SchedTaskExecAction))
                            {
                                SchedTaskExecAction ca = (SchedTaskExecAction) action;

                                ConsoleTable aTable = new ConsoleTable("Execute Action", "");
                                sTable = TableAdd(sTable, "Command", ca.Command);
                                sTable = TableAdd(sTable, "Args", ca.Args);
                                sTable = TableAdd(sTable, "Working Directory", ca.WorkingDir);
                              
                                sb.AppendLine(IndentPara(sTable.ToMarkDownString(), 2));
                            }
                            else if (action.GetType() == typeof(SchedTaskShowMessageAction))
                            {
                                SchedTaskShowMessageAction ca = (SchedTaskShowMessageAction) action;

                                ConsoleTable aTable = new ConsoleTable("Message Action", "");

                                sTable = TableAdd(sTable, "Title", ca.Title);
                                sTable = TableAdd(sTable, "Body", ca.Body);
                                sb.AppendLine(IndentPara(sTable.ToMarkDownString(), 2));
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

                        sb.AppendLine(IndentPara(tTable.ToMarkDownString(), 1));
                    }
                }
                else if (sr.Setting.GetType() == typeof(ScriptSetting))
                {
                    ScriptSetting cs = (ScriptSetting)sr.Setting;

                    ConsoleTable sTable = new ConsoleTable(poltype + " | Setting", "Script");

                    sTable = TableAdd(sTable, "Script Type", cs.ScriptType.ToString());
                    sTable = TableAdd(sTable, "CmdLine", cs.CmdLine);
                    sTable = TableAdd(sTable, "Args", cs.Parameters);

                    sb.AppendLine(IndentPara(sTable.ToMarkDownString(), 1));
                }
                else if (sr.Setting.GetType() == typeof(ShortcutSetting))
                {
                    ShortcutSetting cs = (ShortcutSetting)sr.Setting;

                    ConsoleTable sTable = new ConsoleTable(poltype + " | Setting", "Shortcut");

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

                    sb.AppendLine(IndentPara(sTable.ToMarkDownString(), 1));
                }
                else if (sr.Setting.GetType() == typeof(SystemAccessSetting))
                {
                    SystemAccessSetting cs = (SystemAccessSetting)sr.Setting;

                    ConsoleTable sTable = new ConsoleTable(poltype + " | Setting", "System Access");
                    sTable = TableAdd(sTable, cs.SettingName, cs.ValueString);
                    sb.AppendLine(IndentPara(sTable.ToMarkDownString(), 1));

                }
                else if (sr.Setting.GetType() == typeof(UserSetting))
                {
                    UserSetting cs = (UserSetting)sr.Setting;

                    ConsoleTable sTable = new ConsoleTable(poltype + " | Setting", "User");

                    sTable = TableAdd(sTable, "Name", cs.Name);
                    sTable = TableAdd(sTable, "Action", cs.Action.ToString());
                    sTable = TableAdd(sTable, "UserName", cs.UserName);
                    sTable = TableAdd(sTable, "NewName", cs.NewName);
                    sTable = TableAdd(sTable, "FullName", cs.FullName);
                    sTable = TableAdd(sTable, "Description", cs.Description);
                    sTable = TableAdd(sTable, "Cpassword", cs.Cpassword);
                    sTable = TableAdd(sTable, "Password", cs.Password);
                    sTable = TableAdd(sTable, "PwNeverExpires", cs.PwNeverExpires.ToString());

                    sb.AppendLine(IndentPara(sTable.ToMarkDownString(), 1));
                }
                else
                {

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

            sb.AppendLine(IndentPara(fTable.ToMarkDownString(), 2));

            if (finding.AclResult.Count >= 1)
            {
                sb.AppendLine("...ACL.Finding.Details...");
                sb.AppendLine(PrintNiceAces(finding.AclResult));
                sb.AppendLine("......");
            }

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
                IEnumerable<String> strchunks = ChunksUpto(v2, 80);
                
                bool first = true;
                foreach (string chunk in strchunks)
                {
                    if (first)
                    {
                        table.AddRow(v1, chunk);
                        first = false;
                    }
                    else
                    {
                        table.AddRow("", chunk);
                    }
                }
            }
            else
            {
                table.AddRow(v1, v2);
            }

            return table;
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

        string IndentPara(string inString, int indentfactor)
        {
            string istring = String.Concat(Enumerable.Repeat(" ", (indent * indentfactor)));
            string result = istring + inString.Replace("\n", "\n" + istring);
            return result;
        }
    }
}
