using static LibSnaffle.Classifiers.Rules.Constants;

namespace LibSnaffle.Classifiers.Results
{
    public class ShareResult : Result
    {
        public bool Snaffle { get; set; }
        public bool ScanShare { get; set; }
        public string SharePath { get; set; }
        public bool Listable { get; set; }
        public Triage Triage { get; set; } = Triage.Green;
    }
}
