namespace LibSnaffle.Classifiers.Rules
{
    public static class Constants
    {
        public enum MatchLoc
        {
            ShareName,
            FilePath,
            FileName,
            FileExtension,
            FileContentAsString,
            FileContentAsBytes,
            FileLength,
            FileMD5
        }

        public enum MatchListType
        {
            Exact,
            Contains,
            Regex,
            EndsWith,
            StartsWith
        }

        public enum MatchAction
        {
            Discard,
            SendToNextScope,
            Snaffle,
            Relay,
            CheckForKeys,
            EnterArchive
        }

        public enum Triage
        {
            Green,
            Yellow,
            Red,
            Black
        }
        public enum EnumerationScope
        {
            ShareEnumeration,
            DirectoryEnumeration,
            FileEnumeration,
            ContentsEnumeration
        }
    }
}
