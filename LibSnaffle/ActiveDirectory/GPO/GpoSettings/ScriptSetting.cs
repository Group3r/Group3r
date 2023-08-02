namespace LibSnaffle.ActiveDirectory
{
    public class ScriptSetting : GpoSetting
    {
        public ScriptType ScriptType { get; set; }
        public string CmdLine { get; set; } = "";
        public string Parameters { get; set; } = "";
    }
}
