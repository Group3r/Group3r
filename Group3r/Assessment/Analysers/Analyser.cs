using BigFish.Concurrency;
using BigFish.Options.AssessmentOptions;
using LibSnaffle.Classifiers.Rules;

namespace BigFish.Assessment.Analysers
{
    public abstract class Analyser
    {
        public abstract SettingResult Analyse(AssessmentOptions assessmentOptions);
        public SettingResult SettingResult { get; set; } = new SettingResult();

        public GrouperMq Mq { get; set; }
        public Constants.Triage MinTriage { get; set; }
    }
}