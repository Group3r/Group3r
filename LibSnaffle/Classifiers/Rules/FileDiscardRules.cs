using LibSnaffle.Classifiers.Rules;
using System.Collections.Generic;

namespace LibSnaffle.Classifiers
{
    public partial class ClassifierRules
    {
        private void BuildFileDiscardRules()
        {
            AllClassifierRules.Add(
                new ClassifierRule()
                {
                    Description = "Skip any further scanning for files with these extensions.",
                    RuleName = "DiscardExtExact",
                    EnumerationScope = Constants.EnumerationScope.FileEnumeration,
                    MatchLocation = Constants.MatchLoc.FileExtension,
                    WordListType = Constants.MatchListType.Exact,
                    MatchAction = Constants.MatchAction.Discard,
                    WordList = new List<string>()
                    {
                        // always skip these file extensions
                        // image formats
                        ".bmp", // test file created
                        ".eps", // test file created
                        ".gif", // test file created
                        ".ico", // test file created
                        ".jfi", // test file created
                        ".jfif", // test file created
                        ".jif", // test file created
                        ".jpe", // test file created
                        ".jpeg", // test file created
                        ".jpg", // test file created
                        ".png", // test file created
                        ".psd", // test file created
                        ".svg", // test file created
                        ".tif", // test file created
                        ".tiff", // test file created
                        ".webp", // test file created
                        ".xcf", // test file created
                        // font 
                        ".ttf", // test file created
                        ".otf", // test file created
                        // misc
                        ".lock", // test file created
                        ".css", // test file created
                        ".less" // test file created
                    },
                });
        }
    }
}
