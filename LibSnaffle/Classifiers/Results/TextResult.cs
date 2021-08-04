using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace LibSnaffle.Classifiers.Results
{
    public class TextResult : Result
    {
        public List<string> MatchedStrings { get; set; }
        public string MatchContext { get; set; }
    }
}
