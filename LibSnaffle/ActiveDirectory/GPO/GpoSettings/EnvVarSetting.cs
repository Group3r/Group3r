namespace LibSnaffle.ActiveDirectory
{
    public class EnvVarSetting : GpoSetting
    {
        public string Name { get; set; } = "";
        public string Status { get; set; } = "";
        public SettingAction Action { get; set; }
        public string EnvVarAction { get; set; }
    }
}
