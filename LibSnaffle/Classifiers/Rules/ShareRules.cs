using LibSnaffle.Classifiers.Rules;
using System.Collections.Generic;

namespace LibSnaffle.Classifiers
{
    public partial class ClassifierRules
    {
        private void BuildShareRules()
        {
            AllClassifierRules.Add(new ClassifierRule()
            {
                RuleName = "DiscardShareEndsWith",
                Description = "Skips scanning inside shares ending with these words.",
                EnumerationScope = Constants.EnumerationScope.ShareEnumeration,
                MatchLocation = Constants.MatchLoc.ShareName,
                MatchAction = Constants.MatchAction.Discard,
                WordListType = Constants.MatchListType.EndsWith,
                WordList = new List<string>()
                    {
                        "\\print$",
                        "\\ipc$"
                    },
            });
            AllClassifierRules.Add(new ClassifierRule()
            {
                RuleName = "KeepShareBlack",
                Description = "Notifies the user that they can read C$ or ADMIN$ or something fun/noisy, but doesn't actually scan inside it.",
                EnumerationScope = Constants.EnumerationScope.ShareEnumeration,
                MatchLocation = Constants.MatchLoc.ShareName,
                MatchAction = Constants.MatchAction.Snaffle,
                WordListType = Constants.MatchListType.EndsWith,
                Triage = Constants.Triage.Black,
                WordList = new List<string>()
                    {
                        "\\C$",
                        "\\ADMIN$"
                    },
            });
            /*
            this.ClassifierRules.Add(new ClassifierRule()
            {
                RuleName = "KeepShareRed",
                Description = "Notifies the user that they can read C$ or ADMIN$ or something fun/noisy, but doesn't actually scan inside it.",
                EnumerationScope = EnumerationScope.ShareEnumeration,
                MatchLocation = MatchLoc.ShareName,
                MatchAction = MatchAction.Snaffle,
                WordListType = MatchListType.EndsWith,
                Triage = Triage.Black,
                WordList = new List<string>()
                    {
                        "\\Users",
                    },
            });
            */
        }

        /*
        [Nett.TomlIgnore]
        public string[] ShareStringsToPrioritise { get; set; } =
        {
            // these are substrings that make a share or hostname more interesting and make it worth prioritising.
            "IT",
            "security",
            "admin",
            "dev",
            "sql",
            "backup",
            "sap",
            "erp",
            "oracle",
            "vmware",
            "sccm"
        };
        */
    }
}
