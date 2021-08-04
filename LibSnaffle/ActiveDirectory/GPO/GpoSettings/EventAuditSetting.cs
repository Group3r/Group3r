namespace LibSnaffle.ActiveDirectory
{
    public class EventAuditSetting : GpoSetting
    {
        public string AuditType { get; set; }
        public int AuditLevel { get; set; }
    }
}