using BigFish.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;

namespace BigFish.Assessment.Analysers
{
    public class FolderAnalyser : Analyser
    {
        public FolderSetting setting { get; set; }
        public override SettingResult Analyse(AssessmentOptions assessmentOptions)
        {
            // Nothing particularly sexy or exciting in here.

            if (setting.Source.Contains("NTFRS"))
            {
                setting.IsMorphed = true;
            }

            SettingResult.Setting = setting;

            return SettingResult;
        }
    }
}
