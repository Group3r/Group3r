using LibSnaffle.Classifiers.Rules;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace LibSnaffle.Classifiers
{
    public partial class ClassifierRules
    {
        // Classifiers
        public List<ClassifierRule> AllClassifierRules { get; set; } = new List<ClassifierRule>();
        [Nett.TomlIgnore]
        public List<ClassifierRule> ShareClassifierRules { get; set; } = new List<ClassifierRule>();
        [Nett.TomlIgnore]
        public List<ClassifierRule> DirClassifierRules { get; set; } = new List<ClassifierRule>();
        [Nett.TomlIgnore]
        public List<ClassifierRule> FileClassifierRules { get; set; } = new List<ClassifierRule>();
        [Nett.TomlIgnore]
        public List<ClassifierRule> ContentsClassifierRules { get; set; } = new List<ClassifierRule>();

        public void PrepareClassifiers()
        {
            // Where rules are using regexen, we precompile them here.
            // We're gonna use them a lot so efficiency matters.
            foreach (ClassifierRule classifierRule in AllClassifierRules)
            {
                classifierRule.Regexes = new List<Regex>();
                switch (classifierRule.WordListType)
                {
                    case Constants.MatchListType.Regex:
                        foreach (string pattern in classifierRule.WordList)
                        {
                            classifierRule.Regexes.Add(new Regex(pattern,
                                RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant));
                        }

                        break;
                    case Constants.MatchListType.Contains:
                        classifierRule.Regexes = new List<Regex>();
                        foreach (string word in classifierRule.WordList)
                        {
                            string pattern = Regex.Escape(word);
                            classifierRule.Regexes.Add(new Regex(pattern,
                                RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant));
                        }

                        break;
                    case Constants.MatchListType.EndsWith:
                        foreach (string word in classifierRule.WordList)
                        {
                            string pattern = Regex.Escape(word);
                            pattern = pattern + "$";
                            classifierRule.Regexes.Add(new Regex(pattern,
                                RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant));
                        }

                        break;
                    case Constants.MatchListType.StartsWith:
                        foreach (string word in classifierRule.WordList)
                        {
                            string pattern = Regex.Escape(word);
                            pattern = "^" + pattern;
                            classifierRule.Regexes.Add(new Regex(pattern,
                                RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant));
                        }

                        break;
                    case Constants.MatchListType.Exact:
                        foreach (string word in classifierRule.WordList)
                        {
                            string pattern = Regex.Escape(word);
                            pattern = "^" + pattern + "$";
                            classifierRule.Regexes.Add(new Regex(pattern,
                                RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant));
                        }

                        break;

                }
            }

            // sort everything into enumeration scopes
            ShareClassifierRules = (from classifier in AllClassifierRules
                                where classifier.EnumerationScope == Constants.EnumerationScope.ShareEnumeration
                                select classifier).ToList();
            DirClassifierRules = (from classifier in AllClassifierRules
                              where classifier.EnumerationScope == Constants.EnumerationScope.DirectoryEnumeration
                              select classifier).ToList();
            FileClassifierRules = (from classifier in AllClassifierRules
                               where classifier.EnumerationScope == Constants.EnumerationScope.FileEnumeration
                               select classifier).ToList();
            ContentsClassifierRules = (from classifier in AllClassifierRules
                                   where classifier.EnumerationScope == Constants.EnumerationScope.ContentsEnumeration
                                   select classifier).ToList();
        }

        public void BuildDefaultClassifiers()
        {
            this.AllClassifierRules = new List<ClassifierRule>();
            BuildShareRules();
            BuildPathRules();
            BuildFileDiscardRules();
            BuildFileNameRules();
            BuildFileContentRules();
        }
    }
}