using Group3r.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;

namespace Group3r.Assessment.Analysers
{
    public class EnvVarAnalyser : Analyser
    {
        public EnvVarSetting setting { get; set; }

        public override SettingResult Analyse(AssessmentOptions assessmentOptions)
        {
            // TODO - write analysis via textclassifier to look for creds etc

            /*
            List<GpoFinding> findings = new List<GpoFinding>();

            findings.Add(new GpoFinding()
            {
                //GpoSetting = setting,
                FindingReason = "EnvVar analyser not implemented.",
                FindingDetail = "EnvVar analyser not implemented.",
                Triage = Constants.Triage.Green
            });
                        if (findings.Count > 0)
            {
                this.setting.Findings = findings;
                return true;
            }
                        // put findings in settingResult
            SettingResult.Findings = findings;

            // make a new setting object minus the ugly bits we don't care about.
            SettingResult.Setting = new EnvVarSetting();
            */
            SettingResult.Setting = setting;

            return SettingResult;
        }
    }
}
