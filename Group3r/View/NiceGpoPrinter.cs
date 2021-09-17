using System;
using System.Collections.Generic;
using System.Linq;
using Group3r.Assessment;
using LibSnaffle.ActiveDirectory;
using System.Text;
using Group3r.Options;

namespace Group3r.View
{
    /**
     * Summary: Implementation of IGpoOutputter which just returns nice GPO output.
     */
    class NiceGpoPrinter : IGpoPrinter
    {
        private GrouperOptions grouperOptions;
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

            StringBuilder sb = new StringBuilder();
            sb.AppendLine();
            sb.AppendLine("-------------------------------");
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
            sb.AppendFormat("{0} - {1} - {2}", gpoDisplayName, gpoResult.Attributes.Uid, morphed);
            sb.AppendLine();
            sb.AppendLine("-------------------------------");
            sb.AppendFormat("Date Created: {0}", gpoResult.Attributes.CreatedDate);
            sb.AppendLine();
            sb.AppendFormat("Date Modified: {0}", gpoResult.Attributes.ModifiedDate);
            sb.AppendLine();
            sb.AppendFormat("Path in SYSVOL: {0}", gpoResult.Attributes.PathInSysvol);
            sb.AppendLine();
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
            sb.AppendFormat("Computer Policy: {0}", computerPolicy);
            sb.AppendLine();
            sb.AppendFormat("User Policy: {0}", userPolicy);
            sb.AppendLine();
            foreach (GPOLink gpoLink in gpoResult.Attributes.GpoLinks)
            {
                sb.AppendFormat("Link: {0} ({1})", gpoLink.LinkPath, gpoLink.LinkEnforced);
                sb.AppendLine();
            }
            sb.AppendLine("-------------------------------");
            sb.AppendLine("Findings for GPO Attributes will go here.");
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

            foreach (SettingResult sr in gpoResult.SettingResults)
            {
                if ((sr.Findings.Count == 0) && grouperOptions.FindingsOnly)
                {
                    continue;
                }
                
                if (sr.Findings.Count >= 1)
                {
                    sb.Append("Findings:");

                    foreach (GpoFinding finding in sr.Findings)
                    {
                        sb.Append(PrintNiceFinding(finding));
                    }
                }
                else if (sr.Findings.Count == 0)
                {
                    sb.AppendLine("-------------------------------");
                }

                if (sr.Setting.GetType() == typeof(DataSourceSetting))
                {
                    DataSourceSetting cs = (DataSourceSetting)sr.Setting;
                    sb.AppendLine("____Data_Source_Setting____");
                    if (cs.PolicyType == PolicyType.Computer)
                    {
                        sb.AppendLine("Computer Policy");
                    }
                    else if (cs.PolicyType == PolicyType.User)
                    {
                        sb.AppendLine("UserPolicy");
                    }
                    sb.AppendLine("Name: " + cs.Name);
                    sb.AppendLine("Action: " + cs.Action.ToString());
                    sb.AppendLine("Description: " + cs.Description);
                    sb.AppendLine("Driver: " + cs.Driver);
                    sb.AppendLine("UserName: " + cs.UserName);
                    sb.AppendLine("Cpassword: " + cs.Cpassword);
                    sb.AppendLine("Password:" + cs.Password);
                    sb.AppendLine("DSN: " + cs.DSN);
                }
                else if (sr.Setting.GetType() == typeof(DeviceSetting))
                {
                    DeviceSetting cs = (DeviceSetting)sr.Setting;
                }
                else if (sr.Setting.GetType() == typeof(DriveSetting))
                {
                    DriveSetting cs = (DriveSetting)sr.Setting;
                    sb.AppendLine("____Drive_Setting____");
                    sb.AppendLine("Name: " + cs.Name);
                    sb.AppendLine("Action: " + cs.Action);
                    sb.AppendLine("Path: " + cs.Path);
                    sb.AppendLine("Label: " + cs.Label);
                    sb.AppendLine("Letter: " + cs.Letter);
                    sb.AppendLine("UserName: " + cs.UserName);
                    sb.AppendLine("Cpassword: " + cs.Cpassword);
                    sb.AppendLine("Password: " + cs.Password);
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
                    sb.AppendLine("____File_Setting____");
                    if (cs.PolicyType == PolicyType.Computer)
                    {
                        sb.AppendLine("Computer Policy");
                    }
                    else if (cs.PolicyType == PolicyType.User)
                    {
                        sb.AppendLine("UserPolicy");
                    }
                    sb.AppendLine("Action: " + cs.FileAction);
                    sb.AppendLine("FileName: " + cs.FileName);
                    sb.AppendLine("FromPath: " + cs.FromPath);
                    sb.AppendLine("TargetPath: " + cs.TargetPath);
                }
                else if (sr.Setting.GetType() == typeof(FolderSetting))
                {
                    FolderSetting cs = (FolderSetting)sr.Setting;

                }
                else if (sr.Setting.GetType() == typeof(GroupSetting))
                {
                    GroupSetting cs = (GroupSetting)sr.Setting;
                    sb.AppendLine("____Group_Setting____");
                    if (cs.PolicyType == PolicyType.Computer)
                    {
                        sb.AppendLine("Computer Policy");
                    }
                    else if (cs.PolicyType == PolicyType.User)
                    {
                        sb.AppendLine("UserPolicy");
                    }
                    sb.AppendLine("Name:" + cs.Name);
                    sb.AppendLine("Action: " + cs.Action);
                    sb.AppendLine("NewName: " + cs.NewName);
                    foreach (GroupSettingMember member in cs.Members)
                    {
                        sb.AppendLine("  " + member.Action + " " + member.Name + " " + member.ResolvedName + " " +
                                      member.Sid);
                    }
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
                    sb.AppendLine("____Service_Setting____");
                    if (cs.PolicyType == PolicyType.Computer)
                    {
                        sb.AppendLine("Computer Policy");
                    }
                    else if (cs.PolicyType == PolicyType.User)
                    {
                        sb.AppendLine("UserPolicy");
                    }
                    sb.AppendLine("Name: " + cs.Name);
                    sb.AppendLine("Service Name: " + cs.ServiceName);
                    if (cs.StartupType != null)
                    {
                        sb.Append("Startup Type: ");
                        switch (cs.StartupType)
                        {
                            case "0":
                                sb.AppendLine("Boot");
                                break;
                            case "1":
                                sb.AppendLine("System");
                                break;
                            case "2":
                                sb.AppendLine("Automatic");
                                break;
                            case "3":
                                sb.AppendLine("Manual");
                                break;
                            case "4":
                                sb.AppendLine("Disabled");
                                break;
                        }
                    }

                    sb.AppendLine("Sddl: " + cs.Sddl);
                    sb.AppendLine("Program: " + cs.Program);
                    sb.AppendLine("Args: " + cs.Args);
                    sb.AppendLine("UserName" + cs.UserName);
                    sb.AppendLine("Cpassword" + cs.Cpassword);
                    sb.AppendLine("Password: " + cs.Password);

                }
                else if (sr.Setting.GetType() == typeof(PackageSetting))
                {
                    PackageSetting cs = (PackageSetting)sr.Setting;
                    sb.AppendLine("____Package_Setting____");
                    if (cs.PolicyType == PolicyType.Computer)
                    {
                        sb.AppendLine("Computer Policy");
                    }
                    else if (cs.PolicyType == PolicyType.User)
                    {
                        sb.AppendLine("UserPolicy");
                    }
                    sb.AppendLine("Display Name: " + cs.DisplayName);
                    sb.AppendLine("CreatedDate: " + cs.CreatedDate.ToString());
                    sb.AppendLine("Action: " + cs.PackageAction);
                    sb.AppendLine("Files:");
                    foreach (string file in cs.MsiFileList)
                    {
                        sb.AppendLine("  " + file);
                    }
                    sb.AppendLine("Product Code: " + cs.ProductCode);
                    sb.AppendLine("Upgrade Product Code: " + cs.UpgradeProductCode);
                }
                else if (sr.Setting.GetType() == typeof(PrinterSetting))
                {
                    PrinterSetting cs = (PrinterSetting)sr.Setting;
                    sb.AppendLine("____Printer_Setting____");
                    if (cs.PolicyType == PolicyType.Computer)
                    {
                        sb.AppendLine("Computer Policy");
                    }
                    else if (cs.PolicyType == PolicyType.User)
                    {
                        sb.AppendLine("UserPolicy");
                    }
                    sb.AppendLine("Name: " + cs.Name);
                    sb.AppendLine("Action: " + cs.Action);
                    sb.AppendLine("Comment: " + cs.Comment);
                    sb.AppendLine("Path: " + cs.Path + cs.Port);
                    sb.AppendLine("UserName: " + cs.UserName);
                    sb.AppendLine("Cpassword: " + cs.Cpassword);
                    sb.AppendLine("Password: " + cs.Password);
                }
                else if (sr.Setting.GetType() == typeof(PrivRightSetting))
                {
                    PrivRightSetting cs = (PrivRightSetting)sr.Setting;
                    sb.AppendLine("____User_Rights_Assignment_Setting____");
                    if (cs.PolicyType == PolicyType.Computer)
                    {
                        sb.AppendLine("Computer Policy");
                    }
                    else if (cs.PolicyType == PolicyType.User)
                    {
                        sb.AppendLine("UserPolicy");
                    }
                    sb.AppendLine("Privilege Name: " + cs.Privilege);
                    sb.AppendLine("Trustees: ");
                    foreach (Trustee trustee in cs.Trustees)
                    {
                        if (trustee.DisplayName == "Failed to resolve SID.")
                        {
                            sb.AppendLine("  " + trustee.Sid);
                        }
                        else
                        {
                            sb.AppendLine("  " + trustee.DisplayName + " " + trustee.Sid);
                        }
                    }
                }
                else if (sr.Setting.GetType() == typeof(RegistrySetting))
                {
                    RegistrySetting cs = (RegistrySetting)sr.Setting;
                    sb.AppendLine("____Registry_Setting____");
                    if (cs.PolicyType == PolicyType.Computer)
                    {
                        sb.AppendLine("Computer Policy");
                    }
                    else if (cs.PolicyType == PolicyType.User)
                    {
                        sb.AppendLine("UserPolicy");
                    }
                    sb.AppendLine("Name: " + cs.Name);
                    sb.AppendLine("Action: " + cs.Action.ToString());
                    sb.AppendLine("Key: " + cs.Hive.ToString() + cs.Key);
                    if (cs.Values.Count == 1)
                    {
                        sb.AppendLine("Value Name: " + cs.Values[0].ValueName);
                        sb.AppendLine("Value Name: " + cs.Values[0].ValueName);
                        sb.AppendLine("Value Type: " + cs.Values[0].RegKeyValType);
                        sb.AppendLine("Value: " + cs.Values[0].ValueString);
                    }

                    if (cs.Values.Count > 1)
                    {
                        sb.AppendLine("Values:");
                        foreach (RegistryValue value in cs.Values)
                        {
                            sb.AppendLine("Value Name: " + value.ValueName);
                            sb.AppendLine("Value Type: " + value.RegKeyValType);
                            sb.AppendLine("Value: " + value.ValueString);
                        }
                    }
                }
                else if (sr.Setting.GetType() == typeof(SchedTaskSetting))
                {
                    SchedTaskSetting cs = (SchedTaskSetting)sr.Setting;
                    if (cs.PolicyType == PolicyType.Computer)
                    {
                        sb.AppendLine("Computer Policy");
                    }
                    else if (cs.PolicyType == PolicyType.User)
                    {
                        sb.AppendLine("UserPolicy");
                    }
                    sb.AppendLine("Name: " + cs.Name);
                    sb.AppendLine("Task Type: " + cs.TaskType.ToString());
                    sb.AppendLine("Description: " + cs.Description1);
                    sb.AppendLine("Enabled: " + cs.Enabled.ToString());
                    if (cs.Principals.Count >= 1)
                    {
                        sb.AppendLine("Principals:");
                        int i = 1;
                        foreach (SchedTaskPrincipal principal in cs.Principals)
                        {
                            sb.AppendLine("  Principal " + i.ToString() + ": ");
                            sb.AppendLine("    Id: " + principal.Id);
                            sb.AppendLine("    UserId: " + principal.UserId);
                            sb.AppendLine("    Cpassword: " + principal.Cpassword);
                            sb.AppendLine("    Password: " + principal.Password);
                            sb.AppendLine("    LogonType: " + principal.LogonType);
                            sb.AppendLine("    RunLevel: " + principal.RunLevel);
                        }
                    }
                    if (cs.Actions.Count >= 1)
                    {
                        sb.AppendLine("Actions:");
                        foreach (SchedTaskAction action in cs.Actions)
                        {
                            if (action.GetType() == typeof(SchedTaskEmailAction))
                            {
                                SchedTaskEmailAction ca = (SchedTaskEmailAction) action;
                                sb.AppendLine("  Email Action:");
                                sb.AppendLine("    From: " + ca.From);
                                sb.AppendLine("    To: " + ca.To);
                                sb.AppendLine("    Subject: " + ca.Subject);
                                sb.AppendLine("    Body: " + ca.Body);
                                sb.AppendLine("    Server: " + ca.Server);
                                sb.AppendLine("    Header Fields: " + ca.HeaderFields);
                                if (ca.Attachments.Count >= 1)
                                {
                                    sb.AppendLine("    Attachments: " + ca.HeaderFields);
                                    foreach (string attachment in ca.Attachments)
                                    {
                                        sb.AppendLine("      " + attachment);
                                    }
                                }
                            }
                            else if (action.GetType() == typeof(SchedTaskExecAction))
                            {
                                SchedTaskExecAction ca = (SchedTaskExecAction) action;
                                sb.AppendLine("  Exec Action:");
                                sb.AppendLine("    ");

                            }
                            else if (action.GetType() == typeof(SchedTaskShowMessageAction))
                            {
                                SchedTaskShowMessageAction ca = (SchedTaskShowMessageAction) action;
                                sb.AppendLine("  Show Message Action:");
                                sb.AppendLine("    Title: " + ca.Title);
                                sb.AppendLine("    Body: " + ca.Body);
                            }
                        }
                    }

                    sb.AppendLine("Triggers: ");
                    sb.AppendLine(cs.Triggers.ToString());
                }
                else if (sr.Setting.GetType() == typeof(ScriptSetting))
                {
                    ScriptSetting cs = (ScriptSetting)sr.Setting;
                    sb.AppendLine("____Script_Setting____");
                    if (cs.PolicyType == PolicyType.Computer)
                    {
                        sb.AppendLine("Computer Policy");
                    }
                    else if (cs.PolicyType == PolicyType.User)
                    {
                        sb.AppendLine("UserPolicy");
                    }
                    sb.AppendLine("Script Type: " + cs.ScriptType);
                    sb.AppendLine("CmdLine: " + cs.CmdLine);
                    sb.AppendLine("Args: " + cs.Parameters);
                }
                else if (sr.Setting.GetType() == typeof(ShortcutSetting))
                {
                    ShortcutSetting cs = (ShortcutSetting)sr.Setting;
                    sb.AppendLine("____Shortcut_Setting____");
                    if (cs.PolicyType == PolicyType.Computer)
                    {
                        sb.AppendLine("Computer Policy");
                    }
                    else if (cs.PolicyType == PolicyType.User)
                    {
                        sb.AppendLine("UserPolicy");
                    }
                    sb.AppendLine("Name: " + cs.Name);
                    sb.AppendLine("Action: " + cs.Action.ToString());
                    sb.AppendLine("Comment: " + cs.Comment);
                    sb.AppendLine("Shortcut Path: " + cs.ShortcutPath);
                    sb.AppendLine("Target Type: " + cs.TargetType);
                    sb.AppendLine("Target Path: " + cs.TargetPath);
                    sb.AppendLine("Arguments: " + cs.Arguments);
                    sb.AppendLine("IconPath: " + cs.IconPath);
                    sb.AppendLine("IconIndex: " + cs.IconIndex);
                    sb.AppendLine("Status: " + cs.Status);
                }
                else if (sr.Setting.GetType() == typeof(SystemAccessSetting))
                {
                    SystemAccessSetting cs = (SystemAccessSetting)sr.Setting;
                    sb.AppendLine("____System_Access_Setting____");
                    if (cs.PolicyType == PolicyType.Computer)
                    {
                        sb.AppendLine("Computer Policy");
                    }
                    else if (cs.PolicyType == PolicyType.User)
                    {
                        sb.AppendLine("UserPolicy");
                    }
                    sb.AppendLine(cs.SettingName + ": " + cs.ValueString);

                }
                else if (sr.Setting.GetType() == typeof(UserSetting))
                {
                    UserSetting cs = (UserSetting)sr.Setting;
                    sb.AppendLine("____User_Setting____");
                    if (cs.PolicyType == PolicyType.Computer)
                    {
                        sb.AppendLine("Computer Policy");
                    }
                    else if (cs.PolicyType == PolicyType.User)
                    {
                        sb.AppendLine("UserPolicy");
                    }
                    sb.AppendLine("Name: " + cs.Name);
                    sb.AppendLine("Action: " + cs.Action.ToString());
                    sb.AppendLine("UserName: " + cs.UserName);
                    sb.AppendLine("NewName: " + cs.NewName);
                    sb.AppendLine("FullName: " + cs.FullName);
                    sb.AppendLine("Description: " + cs.Description);
                    sb.AppendLine("Cpassword: " + cs.Cpassword);
                    sb.AppendLine("Password:" + cs.Password);
                    sb.AppendLine("PwNeverExpires: " + cs.PwNeverExpires.ToString());
                }
                else
                {

                }

                sb.AppendLine();
            }



            return sb.ToString();
        }
        string PrintNiceFinding(GpoFinding finding)
        {
            StringBuilder sb = new StringBuilder();

            sb.AppendLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            sb.AppendLine("Triage Rating: " + finding.Triage.ToString());
            sb.AppendLine("Reason: " + finding.FindingReason);
            sb.AppendLine("Detail: " + finding.FindingDetail);

            if (finding.AclResult.Count >= 1)
            {
                sb.AppendLine("...ACL.Finding.Details...");
                sb.AppendLine(PrintNiceAces(finding.AclResult));
                sb.AppendLine("......");

            }

            if (finding.PathFindings.Count >= 1)
            {
                sb.AppendLine("...Path.Finding.Details...");
                sb.AppendLine(PrintNicePathFindings(finding.PathFindings));
                sb.AppendLine("......");
            }
            sb.AppendLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");

            return sb.ToString();
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

        string PrintNicePathFindings(List<PathFinding> pathFindings)
        {
            StringBuilder sb = new StringBuilder();
            foreach (PathFinding pathFinding in pathFindings)
            {
                sb.AppendLine("IS DISPLAYING PATHFINDING MAYBE NOT NECESSARY?");
            }
            return sb.ToString();
        }
    }
}
