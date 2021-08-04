using System;
using System.Collections.Generic;
using Group3r.View;
using LibSnaffle.ActiveDirectory;
using Group3r.Options.AssessmentOptions;

namespace Group3r.Assessment
{
    public class GpoResult
    {
        public GPOAttributes Attributes { get; set; }
        public List<SimpleAce> GpoAclResult { get; set; }

        public List<GpoFinding> GpoAttributeFindings { get; set; }
        public List<SettingResult> SettingResults { get; set; }
        public GpoResult(AssessmentOptions assessmentOptions, GPOAttributes attributes)
        {
            this.Attributes = attributes;
            this.Attributes.NtSecurityDescriptor = null; // null this out for display because we've already parsed it into a semi-readable format
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
                    GpoFinding gpoFinding = new GpoFinding();
                    gpoFinding.AclResult = aclResult;
                    gpoFinding.FindingReason = "Found some interesting ACLs on this GPO. Might wanna check 'em out.";
                    gpoFinding.FindingDetail = "IDK just look at it jeez.";
                    gpoFinding.Triage = LibSnaffle.Classifiers.Rules.Constants.Triage.Black;
                    GpoAttributeFindings.Add(gpoFinding);
                }

                // null these out, we don't want them any more.
                Attributes.NtSecurityDescriptor = null;
                Attributes.NtSecurityDescriptorSddl = null;
            }
        }
    }

    public class SettingResult
    {
        public GpoSetting Setting { get; set; }
        public List<GpoFinding> Findings { get; set; } = new List<GpoFinding>();

    }
}
