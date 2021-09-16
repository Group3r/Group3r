using System.Collections.Generic;

namespace LibSnaffle.ActiveDirectory
{
    public class GroupSetting : GpoSetting
    {
        public string Name { get; set; } = "";
        public string NewName { get; set; } = "";
        public string Description { get; set; }
        public bool DeleteAllGroups { get; set; }
        public bool DeleteAllUsers { get; set; }
        public bool RemoveAccounts { get; set; }
        public SettingAction Action { get; set; }
        public string GroupAction { get; set; }
        public List<GroupSettingMember> Members { get; set; } = new List<GroupSettingMember>();
    }

    public class GroupSettingMember
    {
        public string Name { get; set; }
        public SettingAction Action { get; set; }
        public string Sid { get; set; }
        public string ResolvedName { get; set; }
    }
}
