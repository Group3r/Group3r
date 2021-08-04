using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace LibSnaffle.Classifiers.Results
{

    public class Result
    {
        public ClassifierRule MatchedRule { get; set; }
        public string MatchedString { get; set; }
    }
}
