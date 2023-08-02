using LibSnaffle.Classifiers.Rules;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace LibSnaffle.Classifiers
{
    public class ClassifierRule
    {
        // define in what phase this rule is applied
        public Constants.EnumerationScope EnumerationScope { get; set; } = Constants.EnumerationScope.FileEnumeration;
        // define a way to chain rules together
        public string RuleName { get; set; } = "Default";
        public Constants.MatchAction MatchAction { get; set; } = Constants.MatchAction.Snaffle;
        public string RelayTarget { get; set; } = null;
        public string Description { get; set; } = "A description of what a rule does.";
        // define the behaviour of this rule
        public Constants.MatchLoc MatchLocation { get; set; } = Constants.MatchLoc.FileName;
        public Constants.MatchListType WordListType { get; set; } = Constants.MatchListType.Contains;
        public int MatchLength { get; set; } = 0;
        public string MatchMD5 { get; set; }
        public List<string> WordList { get; set; } = new List<string>();
        public List<Regex> Regexes { get; set; }
        // define the severity of any matches
        public Constants.Triage Triage { get; set; } = Constants.Triage.Green;
    }
}