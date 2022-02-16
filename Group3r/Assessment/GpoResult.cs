using Group3r.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;
using System.Collections.Generic;

namespace Group3r.Assessment
{
    public class GpoResult
    {
        public GPOAttributes Attributes { get; set; }
        public List<SimpleAce> GpoAclResult { get; set; } = new List<SimpleAce>();

        public List<GpoFinding> GpoAttributeFindings { get; set; } = new List<GpoFinding>();
        public List<SettingResult> SettingResults { get; set; } = new List<SettingResult>();
        public GpoResult(AssessmentOptions assessmentOptions, GPOAttributes attributes)
        {
            Attributes = attributes;
            Attributes.NtSecurityDescriptor = null; // null this out for display because we've already parsed it into a semi-readable format
            GetGpoAclResult(assessmentOptions);
        }

        private void GetGpoAclResult(AssessmentOptions assessmentOptions)
        {
            SddlAnalyser sddlAnalyser = new SddlAnalyser(assessmentOptions);

            if (Attributes.NtSecurityDescriptorSddl != null)
            {

                List<SimpleAce> aclResult = sddlAnalyser.AnalyseSddl(Attributes.NtSecurityDescriptorSddl);

                if (aclResult.Count > 0)
                {
                    if (GpoAttributeFindings == null)
                    {
                        GpoAttributeFindings = new List<GpoFinding>();
                    }
                    GpoFinding gpoFinding = new GpoFinding
                    {
                        AclResult = aclResult,
                        FindingReason = "Found some interesting ACLs on this GPO. Might wanna check 'em out.",
                        FindingDetail = "IDK just look at it jeez.",
                        Triage = LibSnaffle.Classifiers.Rules.Constants.Triage.Black
                    };
                    GpoAttributeFindings.Add(gpoFinding);
                }
            }
        }
    }

    public class SettingResult
    {
        public GpoSetting Setting { get; set; }
        public List<GpoFinding> Findings { get; set; } = new List<GpoFinding>();

    }
}
