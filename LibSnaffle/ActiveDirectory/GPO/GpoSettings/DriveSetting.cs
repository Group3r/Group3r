namespace LibSnaffle.ActiveDirectory
{
    public class DriveSetting : GpoSetting
    {
        public string Name { get; set; }
        public SettingAction Action { get; set; }
        public string DriveAction { get; set; }
        public string ThisDrive { get; set; }
        public string AllDrives { get; set; }
        public string UserName { get; set; }
        public string Cpassword { get; set; }
        public string Password { get; set; }
        public string Path { get; set; }
        public string Label { get; set; }
        public string Persistent { get; set; }
        public string Letter { get; set; }
        public string DriveLetter { get; set; }
    }
}
