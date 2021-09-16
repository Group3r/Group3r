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
            if (gpoResult.GpoAttributeFindings.Count >= 1)
            {
                // TODO write GpoAttributeFindings
            }
            sb.AppendLine("-------------------------------");
            if (gpoResult.GpoAclResult.Count >= 1)
            {
                // TODO write gpo ACL results
            }
            sb.AppendLine("-------------------------------");
            
            /*
___________________
$SettingType Finding - {Red}
~~~~~~~~~~~~~~~~~~~
Reason: $REASON
Detail: $DETAIL

Setting Prop1:
Setting Prop2:

___________________
$SettingType
~~~~~~~~~~~~~~~~~~~
Setting Prop1:
Setting Prop2:
*/
 
            foreach (SettingResult sr in gpoResult.SettingResults)
            {
                if ((sr.Findings.Count == 0) && grouperOptions.FindingsOnly)
                {
                    continue;
                }

                if (sr.Setting.GetType() == typeof(DataSourceSetting))
                {
                    DataSourceSetting cs = (DataSourceSetting)sr.Setting;

                }
                else if (sr.Setting.GetType() == typeof(DeviceSetting))
                {
                    DeviceSetting cs = (DeviceSetting)sr.Setting;
                }
                else if (sr.Setting.GetType() == typeof(DriveSetting))
                {
                    DriveSetting cs = (DriveSetting)sr.Setting;

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

                }
                else if (sr.Setting.GetType() == typeof(FolderSetting))
                {
                    FolderSetting cs = (FolderSetting)sr.Setting;

                }
                else if (sr.Setting.GetType() == typeof(GroupSetting))
                {
                    GroupSetting cs = (GroupSetting)sr.Setting;

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

                }
                else if (sr.Setting.GetType() == typeof(PackageSetting))
                {
                    PackageSetting cs = (PackageSetting)sr.Setting;

                }
                else if (sr.Setting.GetType() == typeof(PrinterSetting))
                {
                    PrinterSetting cs = (PrinterSetting)sr.Setting;

                }
                else if (sr.Setting.GetType() == typeof(PrivRightSetting))
                {
                    PrivRightSetting cs = (PrivRightSetting)sr.Setting;

                }
                else if (sr.Setting.GetType() == typeof(RegistrySetting))
                {
                    RegistrySetting cs = (RegistrySetting)sr.Setting;

                }
                else if (sr.Setting.GetType() == typeof(SchedTaskSetting))
                {
                    SchedTaskSetting cs = (SchedTaskSetting)sr.Setting;

                }
                else if (sr.Setting.GetType() == typeof(ScriptSetting))
                {
                    ScriptSetting cs = (ScriptSetting)sr.Setting;

                }
                else if (sr.Setting.GetType() == typeof(ShortcutSetting))
                {
                    ShortcutSetting cs = (ShortcutSetting)sr.Setting;

                }
                else if (sr.Setting.GetType() == typeof(SystemAccessSetting))
                {
                    SystemAccessSetting cs = (SystemAccessSetting)sr.Setting;

                }
                else if (sr.Setting.GetType() == typeof(UserSetting))
                {
                    UserSetting cs = (UserSetting)sr.Setting;

                }
                else
                {

                }
            }



            return sb.ToString();
        }
    }
}
