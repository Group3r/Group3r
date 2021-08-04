using LibSnaffle.Classifiers.Rules;
using System.Collections.Generic;

namespace LibSnaffle.Classifiers
{
    public partial class ClassifierRules
    {
        private void BuildPathRules()
        {
            this.AllClassifierRules.Add(new ClassifierRule()
            {
                Description = "File paths that will be skipped entirely.",
                RuleName = "DiscardFilepathContains",
                EnumerationScope = Constants.EnumerationScope.DirectoryEnumeration,
                MatchLocation = Constants.MatchLoc.FilePath,
                MatchAction = Constants.MatchAction.Discard,
                WordListType = Constants.MatchListType.Contains,
                WordList = new List<string>()
                    {
                        // these are directory names that make us skip a dir instantly when building a tree.
                        "winsxs",
                        "syswow64",
                        "system32",
                        "systemapps",
                        "servicing\\packages",
                        "Microsoft.NET\\Framework",
                        "windows\\immersivecontrolpanel",
                        "windows\\diagnostics",
                        "windows\\debug",
                        "node_modules",
                        "vendor\\bundle",
                        "vendor\\cache",
                        "locale\\",
                        "chocolatey\\helpers",
                        "sources\\sxs",
                        "localization\\",
                        "\\AppData\\Local\\Microsoft\\",
                        "\\AppData\\Roaming\\Microsoft\\",
                        "\\wsuscontent",
                        "\\Application Data\\Microsoft\\CLR Security Config\\"
                    },
            });
        }
    }
}
