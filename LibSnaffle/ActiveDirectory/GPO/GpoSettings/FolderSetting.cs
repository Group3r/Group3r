namespace LibSnaffle.ActiveDirectory
{
    public class FolderSetting : GpoSetting
    {
        public string Name { get; set; }
        public string Status { get; set; }
        public string Image { get; set; }
        public SettingAction Action { get; set; }
        public string FolderAction { get; set; }
        public string Path { get; set; }
        public bool ReadOnly { get; set; }
        public bool Archive { get; set; }
        public bool Hidden { get; set; }
    }
}
