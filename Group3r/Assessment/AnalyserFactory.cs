using Group3r.Assessment.Analysers;
using LibSnaffle.ActiveDirectory;

namespace Group3r.Assessment
{
    public class AnalyserFactory
    {
        public Analyser GetAnalyser(GpoSetting setting)
        {

            if (setting.GetType() == typeof(DataSourceSetting))
            {
                DataSourceSetting castSetting = (DataSourceSetting)setting;
                return new DataSourceAnalyser() { setting = castSetting };
            }
            /*
            else if (setting.GetType() == typeof(DeviceSetting))
            {
                DeviceSetting castSetting = (DeviceSetting)setting;
                return new DeviceAnalyser() { setting = castSetting };
            }
            */
            else if (setting.GetType() == typeof(DriveSetting))
            {
                DriveSetting castSetting = (DriveSetting)setting;
                return new DriveAnalyser() { setting = castSetting };
            }
            /*
            else if (setting.GetType() == typeof(EnvVarSetting))
            {
                EnvVarSetting castSetting = (EnvVarSetting)setting;
                return new EnvVarAnalyser() { setting = castSetting };
            }
            */
            /*
            else if (setting.GetType() == typeof(EventAuditSetting))
            {
                EventAuditSetting castSetting = (EventAuditSetting)setting;
                return new EventAuditAnalyser() { setting = castSetting };
            }
            */
            else if (setting.GetType() == typeof(FileSetting))
            {
                FileSetting castSetting = (FileSetting)setting;
                return new FileAnalyser() { setting = castSetting };
            }
            /*
            else if (setting.GetType() == typeof(FolderSetting))
            {
                FolderSetting castSetting = (FolderSetting)setting;
                return new FolderAnalyser() { setting = castSetting };
            }
            */
            else if (setting.GetType() == typeof(GroupSetting))
            {
                GroupSetting castSetting = (GroupSetting)setting;
                return new GroupAnalyser() { setting = castSetting };
            }
            /*
            else if (setting.GetType() == typeof(IniFileSetting))
            {
                IniFileSetting castSetting = (IniFileSetting)setting;
                return new IniFileAnalyser() { setting = castSetting };
            }
            else if (setting.GetType() == typeof(KerbPolicySetting))
            {
                KerbPolicySetting castSetting = (KerbPolicySetting)setting;
                return new KerbPolicyAnalyser() { setting = castSetting };
            }
            else if (setting.GetType() == typeof(NetOptionSetting))
            {
                NetOptionSetting castSetting = (NetOptionSetting)setting;
                return new NetOptionAnalyser() { setting = castSetting };
            }
            else if (setting.GetType() == typeof(NetworkShareSetting))
            {
                NetworkShareSetting castSetting = (NetworkShareSetting)setting;
                return new NetworkShareAnalyser() { setting = castSetting };
            }
            */
            else if (setting.GetType() == typeof(NtServiceSetting))
            {
                NtServiceSetting castSetting = (NtServiceSetting)setting;
                return new NtServiceAnalyser() { setting = castSetting };
            }
            //else if (setting.GetType() == typeof(PackageSetting))

            if (setting.GetType() == typeof(PackageSetting))
            {
                PackageSetting castSetting = (PackageSetting)setting;
                return new PackageAnalyser() { setting = castSetting };
            }
            else if (setting.GetType() == typeof(PrinterSetting))
            {
                PrinterSetting castSetting = (PrinterSetting)setting;
                return new PrinterAnalyser() { setting = castSetting };
            }
            else if (setting.GetType() == typeof(PrivRightSetting))
            {
                PrivRightSetting castSetting = (PrivRightSetting)setting;
                return new PrivRightAnalyser() { setting = castSetting };
            }
            else if (setting.GetType() == typeof(RegistrySetting))
            {
                RegistrySetting castSetting = (RegistrySetting)setting;
                return new RegistryAnalyser() { setting = castSetting };
            }
            else if (setting.GetType() == typeof(SchedTaskSetting))
            {
                SchedTaskSetting castSetting = (SchedTaskSetting)setting;
                return new SchedTaskAnalyser() { setting = castSetting };
            }
            else if (setting.GetType() == typeof(ScriptSetting))
            {
                ScriptSetting castSetting = (ScriptSetting)setting;
                return new ScriptAnalyser() { setting = castSetting };
            }
            else if (setting.GetType() == typeof(ShortcutSetting))
            {
                ShortcutSetting castSetting = (ShortcutSetting)setting;
                return new ShortcutAnalyser() { setting = castSetting };
            }
            else if (setting.GetType() == typeof(SystemAccessSetting))
            {
                SystemAccessSetting castSetting = (SystemAccessSetting)setting;
                return new SystemAccessAnalyser() { setting = castSetting };
            }
            else if (setting.GetType() == typeof(UserSetting))
            {
                UserSetting castSetting = (UserSetting)setting;
                return new UserAnalyser() { setting = castSetting };
            }
            else
            {
                return null;
                //throw new NotImplementedException("Group3r doesn't have an analyser for the type of setting found in " + setting.Source);
            }
        }
    }
}