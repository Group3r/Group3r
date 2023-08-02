namespace LibSnaffle.ActiveDirectory
{
    public class FileSecuritySetting : GpoSetting
    {
        public string Sddl { get; set; }
        public Sddl.Parser.Sddl ParsedSddl { get; set; }
        public string FileSecPath { get; set; }
        public SecurityInheritanceType SecurityInheritanceType { get; set; }

    }

    public enum SecurityInheritanceType
    {
        NO_REPLACE,
        CONFIGURE_THEN_INHERIT,
        CONFIGURE_THEN_PROPAGATE
    }
}
