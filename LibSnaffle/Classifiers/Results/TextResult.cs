using System.Collections.Generic;

namespace LibSnaffle.Classifiers.Results
{
    public class TextResult : Result
    {
        public List<string> MatchedStrings { get; set; }
        public string MatchContext { get; set; }
    }
}
