namespace LibSnaffle.ActiveDirectory
{
    public class ShortcutSetting : GpoSetting
    {
        public string Name { get; set; }
        public string Status { get; set; }
        public SettingAction Action { get; set; }
        public string ShortcutAction { get; set; }
        public string TargetType { get; set; }
        public string Arguments { get; set; }
        public string IconPath { get; set; }
        public string IconIndex { get; set; }
        public string StartIn { get; set; }
        public string Comment { get; set; }
        public string ShortcutPath { get; set; }
        public string TargetPath { get; set; }
    }
}
