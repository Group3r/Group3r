namespace LibSnaffle.ActiveDirectory
{
    public class FileSetting : GpoSetting
    {
        public string FileName { get; set; } = "";
        public string Status { get; set; } = "";
        public SettingAction Action { get; set; }
        public string FileAction { get; set; }
        public string TargetPath { get; set; } = "";
        public string FromPath { get; set; } = "";
    }
}
