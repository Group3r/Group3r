using BigFish.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;

namespace BigFish.Assessment.Analysers
{
    public class EventAuditAnalyser : Analyser
    {
        public EventAuditSetting setting { get; set; }
        public override SettingResult Analyse(AssessmentOptions assessmentOptions)
        {
            // Nothing interesting enough in here to merit a 'finding'.

            if (setting.Source.Contains("NTFRS"))
            {
                setting.IsMorphed = true;
            }

            SettingResult.Setting = setting;

            return SettingResult;
        }
    }
}