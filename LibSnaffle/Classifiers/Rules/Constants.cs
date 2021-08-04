using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

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
            Black,
            Green,
            Yellow,
            Red
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
