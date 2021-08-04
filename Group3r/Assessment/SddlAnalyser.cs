using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Sddl.Parser;
using Group3r.Options.AssessmentOptions;

namespace Group3r.Assessment
{


    public class SddlAnalyser
    {
        private AssessmentOptions AssessmentOptions { get; set; }
        public SddlAnalyser(AssessmentOptions assessmentOptions)
        {
            this.AssessmentOptions = assessmentOptions;
        }

        public List<SimpleAce> AnalyseSddl(Sddl.Parser.Sddl sddl)
        {
            // simplify it once
            List<SimpleAce> simpleAC = SimplifyAC(sddl);
            // assess and strip out defaults etc
            List<SimpleAce> AclResult = AssessSimpleAC(simpleAC);

            return AclResult;
        }

        public List<SimpleAce> AssessSimpleAC(List<SimpleAce> SimpleAC) 
        {
            List<SimpleAce> aclResult = new List<SimpleAce>();
            // make a new List<SimpleAce> to put the ones that aren't boring into.

            foreach (SimpleAce ace in SimpleAC)
            {
                List<String> intRights = new List<string>();
                foreach (string right in ace.Rights)
                {
                    // check if there's any interesting rights being handed out
                    if (AssessmentOptions.InterestingRights.Contains(right) && ace.ACEType.Equals(ACEType.Allow))
                    {
                        intRights.Add(right);
                    };
                }

                if (intRights.Count > 0) {
                    // iterate over trustees in assessmentoptions
                    foreach (TrusteeOption trustee in AssessmentOptions.TrusteeOptions)
                    {
                        // find the match (if any)
                        if (trustee.DisplayName.ToLower().Equals(ace.Trustee.ToLower()))
                        {
                            if (trustee.LowPriv && intRights.Count > 0)
                            {
                                SimpleAce aceResult = new SimpleAce();
                                aceResult.ACEType = ace.ACEType;
                                aceResult.Trustee = ace.Trustee;
                                aceResult.Rights = ace.Rights;

                                AceFinding aceFinding = new AceFinding();
                                aceFinding.Triage = LibSnaffle.Classifiers.Rules.Constants.Triage.Red;
                                aceFinding.FindingReason = "AccessControl on this object grants interesting privileges to a very common low-privilege group or user.";
                                aceFinding.FindingDetail = ace.Trustee + " was assigned the following rights: " + String.Join(", ", intRights) + ".";
                                aceResult.AceFinding = aceFinding;

                                aclResult.Add(aceResult);
                                break;
                            }
                            else if (trustee.HighPriv)
                            {
                                // boring
                                break;
                            }
                            else if (!trustee.LowPriv)
                            {
                                SimpleAce aceResult = new SimpleAce();
                                aceResult.Trustee = ace.Trustee;
                                aceResult.Rights = ace.Rights;
                                aclResult.Add(aceResult);
                                break;
                            }
                        }
                    }

                    // iterate over users and groups in targettrustees
                    foreach (string trustee in AssessmentOptions.TargetTrustees)
                    {
                        if (trustee.ToLower().Equals(ace.Trustee.ToLower()))
                        {
                            if (intRights.Count > 0)
                            {
                                SimpleAce aceResult = new SimpleAce();
                                aceResult.ACEType = ace.ACEType;
                                aceResult.Trustee = ace.Trustee;
                                aceResult.Rights = ace.Rights;

                                AceFinding aceFinding = new AceFinding();
                                aceFinding.Triage = LibSnaffle.Classifiers.Rules.Constants.Triage.Red;
                                aceFinding.FindingReason = "AccessControl on this object grants interesting privileges to an explicitly targeted user or group.";
                                aceFinding.FindingDetail = "By default this targets the current user and any groups they're a member of. Specifically, " + ace.Trustee + " was assigned the following rights: " + String.Join(", ", intRights) + ".";
                                aceResult.AceFinding = aceFinding;
                            }

                            if (intRights.Count == 0)
                            {
                                SimpleAce aceResult = new SimpleAce();
                                aceResult.ACEType = ace.ACEType;
                                aceResult.Trustee = ace.Trustee;
                                aceResult.Rights = ace.Rights;
                                aclResult.Add(aceResult);
                            }
                        }
                    }
                }
            }
            return aclResult;
        }
        public List<SimpleAce> SimplifyAC(Sddl.Parser.Sddl sddl)
        {
            List<SimpleAce> SimpleAC = new List<SimpleAce>();
            if (sddl.Owner != null)
            {
                if (!String.IsNullOrWhiteSpace(sddl.Owner.Alias))
                {
                    SimpleAC.Add(new SimpleAce() { ACEType = ACEType.Allow, Rights = new string[1] { "Owner" }, Trustee = sddl.Owner.Alias });
                }
            }
            if (sddl.Dacl.Aces.Length > 0)
            {
                foreach (Ace ace in sddl.Dacl.Aces)
                {
                    SimpleAce simpleAce = new SimpleAce();
                    simpleAce.Trustee = ace.AceSid.Alias;
                    switch (ace.AceType)
                    {
                        case "OBJECT_ACCESS_ALLOWED":
                            simpleAce.ACEType = ACEType.Allow;
                            break;
                        case "OBJECT_ACCESS_DENIED":
                            simpleAce.ACEType = ACEType.Deny;
                            break;
                        default:
                            break;
                    }
                    simpleAce.Rights = SimplifyRights(ace.Rights);

                    SimpleAC.Add(simpleAce);
                }
            }
            return SimpleAC;
        }

        public string[] SimplifyRights(string[] rights)
        {
            //TODO actually simplify these? does it matter?
            return rights;
        }
    }

    public class SimpleAce
    {
        public string Trustee { get; set; }
        public ACEType ACEType { get; set; }
        //public List<SimpleRight> Rights { get; set; }
        public string[] Rights { get; set; }
        public AceFinding AceFinding { get; set; }

    }

    public enum SimpleRight
    {
        List,
        Read,
        LimitedWrite,
        Modify,
        Full
    }

    public enum ACEType
    {
        Allow,
        Deny
    }
    public class AceFinding
    {
        public string FindingReason { get; set; }
        public string FindingDetail { get; set; }
        public LibSnaffle.Classifiers.Rules.Constants.Triage Triage { get; set; }
    }
}
