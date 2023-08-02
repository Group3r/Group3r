using BigFish.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;

namespace BigFish.Assessment.Analysers
{
    public class DeviceAnalyser : Analyser
    {
        public DeviceSetting setting { get; set; }

        public override SettingResult Analyse(AssessmentOptions assessmentOptions)
        {
            // No 'finding' level issues in this area.

            if (setting.Source.Contains("NTFRS"))
            {
                setting.IsMorphed = true;
            }

            SettingResult.Setting = setting;

            return SettingResult;
        }
    }
}
