namespace LibSnaffle.Classifiers
{
    public class ClassifierOptions
    {
        public ClassifierRules AllRules { get; set; }
        public int MatchContextBytes { get; set; } = 200;
        public bool CopyFile { get; set; } = false;
        public long MaxSizeToCopy { get; set; } = 10000000;
        public long MaxSizeToGrep { get; set; } = 1000000;
        public string PathToCopyTo { get; set; }
    }
}
