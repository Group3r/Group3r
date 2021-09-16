using System;
using System.Collections.Generic;

namespace LibSnaffle.ActiveDirectory
{
    public class RegistryValue
    {
        public string ValueName { get; set; } // gpp reg settings
        public RegKeyValType RegKeyValType { get; set; } // gpp reg settings "type", registry.pol
        public string ValueSddlString { get; set; } //
        public Sddl.Parser.Sddl ParsedValueSddl { get; set; } //
        public byte[] ValueBytes { get; set; }  // registry.pol
        public string ValueString { get; set; }
    }

    public class RegistrySetting : GpoSetting
    {
        public string Name { get; set; } // gpp reg settings
        public string Status { get; set; } // gpp reg settings
        public SettingAction Action { get; set; } // gpp reg settings
        public string RegistryAction { get; set; }
        public string DisplayDecimal { get; set; } // gpp reg settings
        public string Default { get; set; } // gpp reg settings
        public DateTime Changed { get; set; }

        // hive and key
        public RegHive Hive { get; set; } // gpp reg settings
        public string Key { get; set; } // gpp reg settings
        public string KeySddlString { get; set; } // .inf "registry keys"
        public Sddl.Parser.Sddl ParsedKeySddl { get; set; } //  .inf "registry keys"
        public string Inheritance { get; set; } // .inf "registry keys"
        public List<RegistryValue> Values { get; set; } = new List<RegistryValue>(); // 

        public void RegHiveFromString(string hiveString)
        {
            switch (hiveString)
            {
                case "MACHINE":
                    Hive = RegHive.HKEY_LOCAL_MACHINE;
                    break;
                default:
                    throw new NotImplementedException("Found a registry hive short name I don't recognise in RegHiveFromString");
                    break;
            }
        }
    }

    public enum RegKeyValType : uint
    {
        REG_NONE = 0,
        REG_SZ = 1,       /* string type (ASCII) */
        REG_EXPAND_SZ = 2,       /* string, includes %ENVVAR% (expanded by caller) (ASCII) */
        REG_BINARY = 3,      /* binary format, callerspecific */
        REG_DWORD = 4,       /* DWORD in little endian format */
        REG_DWORD_BIG_ENDIAN = 5,       /* DWORD in big endian format  */
        REG_LINK = 6,       /* symbolic link (UNICODE) */
        REG_MULTI_SZ = 7,       /* multiple strings, delimited by \0, terminated by \0\0 (ASCII) */
        REG_RESOURCE_LIST = 8,
        REG_FULL_RESOURCE_DESCRIPTOR = 9,
        REG_RESOURCE_REQUIREMENTS_LIST = 10,
        REG_QWORD = 11
    }

    public enum RegHive
    {
        HKEY_CLASSES_ROOT,
        HKEY_CURRENT_USER,
        HKEY_LOCAL_MACHINE,
        HKEY_USERS,
        HKEY_CURRENT_CONFIG
    }
}
