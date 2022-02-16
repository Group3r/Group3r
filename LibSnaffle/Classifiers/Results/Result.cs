namespace LibSnaffle.Classifiers.Results
{

    public class Result
    {
        public ClassifierRule MatchedRule { get; set; }
        public string MatchedString { get; set; }
        public RwStatus RwStatus { get; set; }
    }

    public class RwStatus
    {
        public bool Exists { get; set; }
        public bool CanRead { get; set; }
        public bool CanWrite { get; set; }
        public bool CanModify { get; set; }
    }
}
