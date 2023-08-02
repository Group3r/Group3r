namespace LibSnaffle.ActiveDirectory
{
    public class NetworkShareSetting : GpoSetting
    {
        public string Name { get; set; }
        public SettingAction Action { get; set; }
        public string NetworkShareAction { get; set; }
        public string Path { get; set; }
        public string LimitUsers { get; set; }
        public string Abe { get; set; }
        public string AllRegular { get; set; }
        public string AllHidden { get; set; }
        public string AllAdminDrive { get; set; }
        public string Comment { get; set; }
    }
}
