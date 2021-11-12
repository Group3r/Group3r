using LibSnaffle.Concurrency;
using System;
using System.IO;
using System.Text;
using System.Xml;

namespace LibSnaffle.ActiveDirectory
{
    /// <summary>
    /// Represents an .inf file found within a GPO directory.
    /// </summary>
    public class XmlGpoFile : GpoFile
    {

        public XmlGpoFile(string filepath, FileInfo info, BlockingMq logger) : base(filepath, info, logger)
        {
        }

        public override void Parse()
        {
            GetSettings();
        }

        private XmlDocument ContentXML()
        {
            XmlDocument doc = new XmlDocument();
            doc.Load(FilePath);
            return doc;
        }
        public void GetSettings()
        {
            // Load the document and set the root element.  
            XmlDocument doc = ContentXML();
            XmlNode root = doc.DocumentElement;
            try
            {
                switch (root.Name)
                {
                    case "Groups":
                        XmlNodeList groupNodeList = root.SelectNodes("Group");
                        foreach (XmlNode group in groupNodeList)
                        {
                            GroupSetting groupSetting = new GroupSetting() { Source = FilePath };
                            XmlAttributeCollection groupAttributes = group.Attributes;
                            groupSetting.Name = groupAttributes.GetNamedItem("name").Value;
                            XmlNode groupProperties = group.SelectSingleNode("Properties");
                            XmlAttributeCollection groupPropertiesAttributes = groupProperties.Attributes;
                            groupSetting.NewName = groupPropertiesAttributes?["newName"]?.Value;
                            groupSetting.Action =
                                groupSetting.ParseSettingAction(groupPropertiesAttributes?["action"]?.Value);
                            bool thing;
                            if (bool.TryParse(groupPropertiesAttributes?["deleteAllGroups"]?.Value, out thing))
                            {
                                groupSetting.DeleteAllGroups = thing;
                            }
                            bool thing2;
                            if (Boolean.TryParse(groupPropertiesAttributes?["deleteAllUsers"]?.Value, out thing2))
                            {
                                groupSetting.DeleteAllUsers = thing2;
                            }
                            bool thing3;
                            if (Boolean.TryParse(groupPropertiesAttributes?["removeAccounts"]?.Value, out thing3))
                            {
                                groupSetting.RemoveAccounts = thing3;
                            }
                            groupSetting.Description = groupPropertiesAttributes?["description"]?.Value;
                            XmlNodeList groupMembers = groupProperties?["Members"]?.ChildNodes;
                            if (groupMembers != null)
                            {
                                foreach (XmlNode groupMember in groupMembers)
                                {
                                    XmlAttributeCollection groupMemberAttributes = groupMember.Attributes;
                                    GroupSettingMember groupSettingMember = new GroupSettingMember
                                    {
                                        Action =
                                        groupSetting.ParseSettingAction(
                                            groupMemberAttributes?["action"]?.Value),
                                        Name = groupMemberAttributes?["name"]?.Value,
                                        Sid = groupMemberAttributes?["sid"]?.Value
                                    };
                                    groupSetting.Members.Add(groupSettingMember);
                                }
                            }
                            Settings.Add(groupSetting);
                        }

                        XmlNodeList userNodeList = root.SelectNodes("User");
                        foreach (XmlNode user in userNodeList)
                        {
                            UserSetting userSetting = new UserSetting() { Source = FilePath };
                            XmlAttributeCollection userAttributes = user.Attributes;
                            userSetting.Name = userAttributes?["name"]?.Value;
                            XmlNode userProperties = user.SelectSingleNode("Properties");
                            XmlAttributeCollection userPropertiesAttributes = userProperties.Attributes;
                            userSetting.NewName = userPropertiesAttributes?["newName"]?.Value;
                            userSetting.Action =
                                userSetting.ParseSettingAction(userPropertiesAttributes?["action"]?.Value);
                            userSetting.FullName = userPropertiesAttributes?["fullName"]?.Value;
                            userSetting.Cpassword = userPropertiesAttributes?["cpassword"]?.Value;
                            userSetting.Password = userSetting.DecryptCpassword(userSetting.Cpassword);
                            userSetting.Description = userPropertiesAttributes?["description"]?.Value;
                            userSetting.UserName = userPropertiesAttributes?["userName"]?.Value;
                            bool thing4;
                            if (Boolean.TryParse(userPropertiesAttributes?["acctDisabled"]?.Value, out thing4))
                            {
                                userSetting.AccountDisabled = thing4;
                            }
                            bool thing5;
                            if (Boolean.TryParse(userPropertiesAttributes?["neverExpires"]?.Value, out thing5))
                            {
                                userSetting.PwNeverExpires = thing5;
                            }
                            Settings.Add(userSetting);
                        }
                        return;
                    case "DataSources":
                        XmlNodeList dsNodeList = root.SelectNodes("DataSource");
                        foreach (XmlNode ds in dsNodeList)
                        {
                            DataSourceSetting dsSetting = new DataSourceSetting() { Source = FilePath };
                            XmlAttributeCollection dsAttributes = ds.Attributes;
                            XmlNode dsProperties = ds.SelectSingleNode("Properties");
                            XmlAttributeCollection dsPropAtts = dsProperties.Attributes;

                            dsSetting.Name = dsAttributes?["name"].Value;
                            dsSetting.Action =
                                dsSetting.ParseSettingAction(dsPropAtts?["action"]?.Value);
                            dsSetting.DSN = dsPropAtts?["dsn"]?.Value;
                            dsSetting.Cpassword = dsPropAtts?["cpassword"]?.Value;
                            dsSetting.Password = dsSetting.DecryptCpassword(dsSetting.Cpassword);
                            dsSetting.Description = dsPropAtts?["description"]?.Value;
                            dsSetting.Driver = dsPropAtts?["driver"]?.Value;
                            dsSetting.UserName = dsPropAtts?["username"]?.Value;
                            Settings.Add(dsSetting);
                        }

                        return;
                    case "Drives":
                        XmlNodeList driveNodeList = root.SelectNodes("Drive");
                        foreach (XmlNode drive in driveNodeList)
                        {
                            DriveSetting driveSetting = new DriveSetting() { Source = FilePath };
                            XmlAttributeCollection driveAttributes = drive.Attributes;
                            XmlNode driveProperties = drive.SelectSingleNode("Properties");
                            XmlAttributeCollection drivePropAtts = driveProperties.Attributes;
                            driveSetting.Name = driveAttributes?["name"].Value;
                            driveSetting.Action =
                                driveSetting.ParseSettingAction(drivePropAtts?["action"]?.Value);
                            driveSetting.DriveLetter = drivePropAtts?["useLetter"]?.Value;
                            driveSetting.ThisDrive = drivePropAtts?["thisDrive"]?.Value;
                            driveSetting.AllDrives = drivePropAtts?["allDrives"]?.Value;
                            driveSetting.UserName = drivePropAtts?["userName"]?.Value;
                            driveSetting.Cpassword = drivePropAtts?["cpassword"]?.Value;
                            driveSetting.Password = driveSetting.DecryptCpassword(driveSetting.Cpassword);
                            driveSetting.Path = drivePropAtts?["path"]?.Value;
                            driveSetting.Label = drivePropAtts?["label"]?.Value;
                            driveSetting.Persistent = drivePropAtts?["persistent"]?.Value;
                            driveSetting.Letter = drivePropAtts?["letter"]?.Value;
                            Settings.Add(driveSetting);
                        }
                        break;
                    case "EnvironmentVariables":
                        XmlNodeList evNodeList = root.SelectNodes("EnvironmentVariable");
                        foreach (XmlNode ev in evNodeList)
                        {
                            EnvVarSetting evSetting = new EnvVarSetting() { Source = FilePath };
                            XmlAttributeCollection evAttributes = ev.Attributes;
                            XmlNode evProperties = ev.SelectSingleNode("Properties");
                            XmlAttributeCollection evPropAtts = evProperties.Attributes;

                            evSetting.Name = evAttributes?["name"]?.Value;
                            evSetting.Status = evAttributes?["status"]?.Value;
                            evSetting.Action =
                                evSetting.ParseSettingAction(evPropAtts?["action"]?.Value);
                            Settings.Add(evSetting);
                        }
                        break;
                    case "Files":
                        XmlNodeList fileNodeList = root.SelectNodes("File");
                        foreach (XmlNode file in fileNodeList)
                        {
                            FileSetting fileSetting = new FileSetting() { Source = FilePath };
                            XmlAttributeCollection fileAttributes = file.Attributes;
                            XmlNode fileProperties = file.SelectSingleNode("Properties");
                            XmlAttributeCollection filePropAtts = fileProperties.Attributes;
                            fileSetting.FileName = fileAttributes?["name"]?.Value;
                            fileSetting.Status = fileAttributes?["status"]?.Value;
                            fileSetting.Action =
                                fileSetting.ParseSettingAction(filePropAtts?["action"]?.Value);
                            fileSetting.FromPath = filePropAtts?["fromPath"]?.Value;
                            fileSetting.TargetPath = filePropAtts?["targetPath"]?.Value;
                            Settings.Add(fileSetting);
                        }
                        break;
                    case "IniFiles":
                        XmlNodeList ifNodeList = root.SelectNodes("Ini");
                        foreach (XmlNode iniFile in ifNodeList)
                        {
                            IniFileSetting ifSetting = new IniFileSetting() { Source = FilePath };
                            XmlAttributeCollection ifAttributes = iniFile.Attributes;
                            XmlNode ifProperties = iniFile.SelectSingleNode("Properties");
                            XmlAttributeCollection ifPropAtts = ifProperties.Attributes;
                            ifSetting.Path = ifPropAtts?["path"]?.Value;
                            ifSetting.Section = ifPropAtts?["section"]?.Value;
                            ifSetting.Value = ifPropAtts?["value"]?.Value;
                            ifSetting.Property = ifPropAtts?["property"]?.Value;
                            ifSetting.ParseSettingAction(ifPropAtts?["action"]?.Value);

                            Settings.Add(ifSetting);
                        }
                        break;
                    case "NetworkOptions":
                        XmlNodeList noNodeList = root.SelectNodes("NetworkOption");
                        foreach (XmlNode no in noNodeList)
                        {
                            NetOptionSetting netoptionSetting = new NetOptionSetting() { Source = FilePath };
                            XmlAttributeCollection noAttributes = no.Attributes;
                            XmlNode noProperties = no.SelectSingleNode("Properties");
                            XmlAttributeCollection noPropAtts = noProperties.Attributes;

                            Settings.Add(netoptionSetting);
                        }
                        if (Logger != null)
                        {
                            Logger.Degub("LibSnaffle doesn't properly parse NetworkOptions.xml files. ");
                        }
                        break;
                    case "NetworkShareSettings":
                        XmlNodeList nsNodeList = root.SelectNodes("NetworkShare");
                        foreach (XmlNode ns in nsNodeList)
                        {
                            NetworkShareSetting nsSetting = new NetworkShareSetting() { Source = FilePath };
                            XmlAttributeCollection nsAttributes = ns.Attributes;
                            XmlNode nsProperties = ns.SelectSingleNode("Properties");
                            XmlAttributeCollection nsPropAtts = nsProperties.Attributes;

                            nsSetting.Name = nsAttributes?["name"]?.Value;
                            nsSetting.Action =
                                nsSetting.ParseSettingAction(nsPropAtts?["action"]?.Value);
                            nsSetting.Comment = nsPropAtts?["comment"]?.Value;
                            nsSetting.Path = nsPropAtts?["path"]?.Value;
                            nsSetting.AllRegular = nsPropAtts?["allRegular"]?.Value;
                            nsSetting.AllHidden = nsPropAtts?["allHidden"]?.Value;
                            nsSetting.AllAdminDrive = nsPropAtts?["allAdminDrive"]?.Value;
                            nsSetting.LimitUsers = nsPropAtts?["limitUsers"]?.Value;
                            nsSetting.Abe = nsPropAtts?["abe"]?.Value;
                            Settings.Add(nsSetting);
                        }
                        break;
                    case "NTServices":
                        XmlNodeList serviceNodeList = root.SelectNodes("NTService");
                        foreach (XmlNode service in serviceNodeList)
                        {
                            NtServiceSetting serviceSetting = new NtServiceSetting() { Source = FilePath };
                            XmlAttributeCollection serviceAttributes = service.Attributes;
                            XmlNode serviceProperties = service.SelectSingleNode("Properties");
                            XmlAttributeCollection servicePropAtts = serviceProperties.Attributes;

                            serviceSetting.Name = serviceAttributes?["name"]?.Value;
                            serviceSetting.ServiceName = servicePropAtts?["serviceName"]?.Value;
                            serviceSetting.ServiceAction = servicePropAtts?["serviceAction"]?.Value;
                            serviceSetting.Timeout = servicePropAtts?["timeout"]?.Value;
                            serviceSetting.Program = servicePropAtts?["program"]?.Value;
                            serviceSetting.Args = servicePropAtts?["arguments"]?.Value;
                            serviceSetting.StartupType = servicePropAtts?["startupType"]?.Value;
                            serviceSetting.AccountName = servicePropAtts?["accountName"]?.Value;
                            serviceSetting.UserName = servicePropAtts?["userName"]?.Value;
                            serviceSetting.Cpassword = servicePropAtts?["cpassword"]?.Value;
                            serviceSetting.Password = serviceSetting.DecryptCpassword(serviceSetting.Cpassword);
                            serviceSetting.ActionOnFirstFailure = servicePropAtts?["firstFailure"]?.Value;
                            serviceSetting.ResetFailCountDelay = servicePropAtts?["resetFailCountDelay"]?.Value;
                            serviceSetting.Append = servicePropAtts?["append"]?.Value;
                            serviceSetting.Interact = servicePropAtts?["interact"]?.Value;
                            Settings.Add(serviceSetting);
                        }
                        break;
                    case "Printers":
                        XmlNodeList printerNodeList = root.SelectNodes("SharedPrinter");
                        foreach (XmlNode printer in printerNodeList)
                        {
                            PrinterSetting printerSetting = new PrinterSetting() { Source = FilePath };
                            XmlAttributeCollection printerAttributes = printer.Attributes;
                            XmlNode printerProperties = printer.SelectSingleNode("Properties");
                            XmlAttributeCollection printerPropAtts = printerProperties.Attributes;
                            printerSetting.Name = printerAttributes?["name"]?.Value;
                            printerSetting.UserName = printerPropAtts?["userName"]?.Value;
                            printerSetting.Cpassword = printerPropAtts?["cpassword"]?.Value;
                            printerSetting.Password = printerSetting.DecryptCpassword(printerSetting.Cpassword);
                            printerSetting.Action =
                                printerSetting.ParseSettingAction(printerPropAtts?["action"]?.Value);
                            printerSetting.Path = printerPropAtts?["path"]?.Value;
                            printerSetting.Port = printerPropAtts?["port"]?.Value;
                            printerSetting.Comment = printerPropAtts?["comment"]?.Value;
                            Settings.Add(printerSetting);
                        }
                        break;
                    case "ScheduledTasks":
                        XmlNodeList schedTaskNodeList = root.SelectNodes("Task");
                        XmlNodeList schedTaskV2NodeList = root.SelectNodes("TaskV2");
                        XmlNodeList immediateTaskNodeList = root.SelectNodes("ImmediateTask");
                        XmlNodeList immediateTaskV2NodeList = root.SelectNodes("ImmediateTaskV2");
                        SchedTaskParser stParser = new SchedTaskParser();
                        SchedTaskV2Parser stv2Parser = new SchedTaskV2Parser();
                        foreach (XmlNode schedTask in schedTaskNodeList)
                        {
                            SchedTaskSetting sts = stParser.ParseSchedTask(SchedTaskType.Task, schedTask);
                            Settings.Add(sts);
                        }
                        foreach (XmlNode schedTask in schedTaskV2NodeList)
                        {
                            SchedTaskSetting sts = stv2Parser.ParseSchedTask(SchedTaskType.TaskV2, schedTask);
                            Settings.Add(sts);
                        }
                        foreach (XmlNode schedTask in immediateTaskNodeList)
                        {
                            SchedTaskSetting sts = stParser.ParseSchedTask(SchedTaskType.ImmediateTask, schedTask);
                            Settings.Add(sts);
                        }
                        foreach (XmlNode schedTask in immediateTaskV2NodeList)
                        {
                            SchedTaskSetting sts = stv2Parser.ParseSchedTask(SchedTaskType.ImmediateTaskV2, schedTask);
                            Settings.Add(sts);
                        }
                        break;
                    case "Shortcuts":
                        XmlNodeList shortcutNodeList = root.SelectNodes("Shortcut");
                        foreach (XmlNode shortcut in shortcutNodeList)
                        {
                            ShortcutSetting shortcutSetting = new ShortcutSetting() { Source = FilePath };
                            XmlAttributeCollection shortcutAttributes = shortcut.Attributes;
                            XmlNode shortcutProperties = shortcut.SelectSingleNode("Properties");
                            XmlAttributeCollection shortcutPropAtts = shortcutProperties.Attributes;

                            shortcutSetting.Name = shortcutAttributes?["name"]?.Value;
                            shortcutSetting.Status = shortcutAttributes?["status"]?.Value;
                            shortcutSetting.TargetType = shortcutPropAtts?["targetType"]?.Value;
                            shortcutSetting.TargetPath = shortcutPropAtts?["targetPath"]?.Value;
                            shortcutSetting.Arguments = shortcutAttributes?["arguments"]?.Value;
                            shortcutSetting.Comment = shortcutPropAtts?["comment"]?.Value;
                            shortcutSetting.ShortcutPath = shortcutPropAtts?["shortcutPath"]?.Value;
                            shortcutSetting.IconPath = shortcutPropAtts?["iconPath"]?.Value;
                            shortcutSetting.IconIndex = shortcutPropAtts?["iconIndex"]?.Value;
                            shortcutSetting.StartIn = shortcutPropAtts?["startIn"]?.Value;
                            shortcutSetting.Action =
                                shortcutSetting.ParseSettingAction(shortcutPropAtts?["action"]?.Value);
                            Settings.Add(shortcutSetting);
                        }
                        break;
                    case "RegistrySettings":

                        XmlNodeList rsNodeList = root.SelectNodes("//Registry");

                        foreach (XmlNode rsNode in rsNodeList)
                        {
                            RegistrySetting rs = new RegistrySetting();
                            XmlAttributeCollection rsAttributes = rsNode.Attributes;
                            XmlNode rsProperties = rsNode.SelectSingleNode("Properties");
                            XmlAttributeCollection rsPropAtts = rsProperties.Attributes;

                            // stuff about the setting
                            rs.Name = rsAttributes?["name"]?.Value;
                            rs.Status = rsAttributes?["status"]?.Value;
                            DateTime changed = new DateTime();
                            if (DateTime.TryParse(rsAttributes?["changed"]?.Value, out changed))
                            {
                                rs.Changed = changed;
                            }
                            // stuff about the key
                            rs.Action =
                                rs.ParseSettingAction(rsPropAtts?["action"]?.Value);
                            rs.DisplayDecimal = rsAttributes?["displayDecimal"]?.Value;
                            rs.Default = rsPropAtts?["default"]?.Value;
                            // default to hklm and then try to parse the real value
                            string hiveString = rsPropAtts?["hive"]?.Value;
                            RegHive regHive = RegHive.HKEY_LOCAL_MACHINE;
                            RegHive.TryParse(hiveString, out regHive);
                            rs.Hive = regHive;
                            rs.Key = rsPropAtts?["key"]?.Value;

                            //stuff about the value. make a value and put stuff in it.
                            RegistryValue regVal = new RegistryValue
                            {
                                ValueName = rsPropAtts?["name"]?.Value
                            };
                            // make a val type to parse into
                            RegKeyValType valType = RegKeyValType.REG_NONE;
                            // try to parse it
                            RegKeyValType.TryParse(rsPropAtts?["type"]?.Value, out valType);
                            regVal.RegKeyValType = valType;
                            // get the actual value
                            regVal.ValueBytes = Encoding.Unicode.GetBytes(rsPropAtts?["value"]?.Value);
                            regVal.ValueString = rsPropAtts?["value"]?.Value;
                            rs.Values.Add(regVal);
                            Settings.Add(rs);
                        }
                        break;
                    case "Devices":
                        XmlNodeList devicesNodeList = root.SelectNodes("Device");
                        foreach (XmlNode device in devicesNodeList)
                        {
                            DeviceSetting deviceSetting = new DeviceSetting() { Source = FilePath };
                            XmlAttributeCollection deviceAttributes = device.Attributes;
                            XmlNode deviceProperties = device.SelectSingleNode("Properties");
                            XmlAttributeCollection devicePropAtts = deviceProperties.Attributes;
                            deviceSetting.Name = deviceAttributes?["name"]?.Value;
                            deviceSetting.DeviceClass = devicePropAtts?["deviceClass"]?.Value;
                            deviceSetting.DeviceAction = devicePropAtts?["deviceAction"]?.Value;
                            deviceSetting.DeviceClassGUID = devicePropAtts?["deviceClassGUID"]?.Value;
                            deviceSetting.DeviceType = devicePropAtts?["deviceType"]?.Value;
                            deviceSetting.DeviceTypeID = devicePropAtts?["deviceTypeID"]?.Value;
                            Settings.Add(deviceSetting);
                        }
                        break;
                    case "Folders":
                        XmlNodeList folderNodeList = root.SelectNodes("Folder");
                        foreach (XmlNode folder in folderNodeList)
                        {
                            FolderSetting folderSetting = new FolderSetting() { Source = FilePath };
                            XmlAttributeCollection folderAttributes = folder.Attributes;
                            XmlNode folderProperties = folder.SelectSingleNode("Properties");
                            XmlAttributeCollection folderPropAtts = folderProperties.Attributes;
                            folderSetting.Name = folderAttributes?["name"]?.Value;
                            folderSetting.Status = folderAttributes?["status"]?.Value;
                            folderSetting.Action =
                                folderSetting.ParseSettingAction(folderPropAtts?["action"]?.Value);
                            folderSetting.Path = folderPropAtts?["path"]?.Value;
                            Settings.Add(folderSetting);
                        }
                        break;
                    case "InternetSettings":
                        XmlNodeList inetNodeList = root.SelectNodes("InternetSettings");
                        foreach (XmlNode inet in inetNodeList)
                        {
                            Logger.Degub("LibSnaffle still doesn't parse InternetSettings xml.");
                        }
                        break;
                    default:
                        if (Logger != null)
                        {
                            Logger.Degub(root.Name + " didn't seem to have a handler in the XmlParser switch case thing.");
                        }
                        return;
                }
            }
            catch (Exception e)
            {
                if (Logger != null)
                {
                    Logger.Error(e.ToString());
                }
            }
        }
    }
}
