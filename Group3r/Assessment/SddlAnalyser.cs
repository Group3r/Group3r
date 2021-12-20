using Group3r.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;
using Sddl.Parser;
using System;
using System.Collections.Generic;

namespace Group3r.Assessment
{
    public class SddlAnalyser
    {
        private AssessmentOptions AssessmentOptions { get; set; }
        public SddlAnalyser(AssessmentOptions assessmentOptions)
        {
            AssessmentOptions = assessmentOptions;
        }

        public List<SimpleAce> AnalyseSddl(Sddl.Parser.Sddl sddl)
        {
            // simplify it once
            List<SimpleAce> simpleAC = SimplifyAC(sddl);

            return simpleAC;
        }


        public List<SimpleAce> SimplifyAC(Sddl.Parser.Sddl sddl)
        {
            List<SimpleAce> SimpleAcl = new List<SimpleAce>();
            if (sddl.Owner != null)
            {
                if (!String.IsNullOrWhiteSpace(sddl.Owner.Alias))
                {
                    SimpleAcl.Add(new SimpleAce() { ACEType = ACEType.Allow, Rights = new string[1] { "Owner" }, Trustee = new Trustee() { DisplayName = sddl.Owner.Alias } });
                }
            }
            if (sddl.Dacl.Aces.Length > 0)
            {
                foreach (Ace ace in sddl.Dacl.Aces)
                {
                    SimpleAce simpleAce = new SimpleAce
                    {
                        Trustee = new Trustee()
                        {
                            DisplayName = ace.AceSid.Alias,
                            Sid = ace.AceSid.Raw
                        }
                    };
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

                    SimpleAcl.Add(simpleAce);
                }
            }
            return SimpleAcl;
        }

        public string[] SimplifyRights(string[] rights)
        {
            //TODO actually simplify these? does it matter?
            return rights;
        }
        /*
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

                if (intRights.Count > 0)
                {
                    // iterate over trustees in assessmentoptions
                    foreach (TrusteeOption trustee in AssessmentOptions.TrusteeOptions)
                    {
                        bool displayNameMatch = false;
                        bool fullSidMatch = false;
                        bool domainSidMatch = false;

                        // be a bit thorough about checking for a match
                        if (trustee.DisplayName.ToLower().Equals(ace.TrusteeAlias.ToLower()))
                        {
                            displayNameMatch = true;
                        }
                        if (!String.IsNullOrWhiteSpace(ace.TrusteeSid))
                        {
                            if (trustee.SID.ToLower().Equals(ace.TrusteeSid.ToLower()))
                            {
                                fullSidMatch = true;
                            }

                            if (trustee.DomainSID && ace.TrusteeSid.Contains("-"))
                            {
                                try
                                {
                                    string[] aceSidArray = ace.TrusteeSid.Split('-');
                                    string[] trusteeSidArray = trustee.SID.Split('-');
                                    if (aceSidArray[7] == trusteeSidArray[5])
                                    {
                                        domainSidMatch = true;
                                    }
                                }
                                catch (Exception e)
                                {
                                    Console.WriteLine(e.ToString());
                                }
                            }
                        }

                        // HERE

                        if (displayNameMatch || fullSidMatch || domainSidMatch)
                        {
                            if (trustee.LowPriv && intRights.Count > 0)
                            {
                                SimpleAce aceResult = new SimpleAce
                                {
                                    ACEType = ace.ACEType,
                                    Trustee = ace.Trustee,
                                    Rights = ace.Rights
                                };

                                AceFinding aceFinding = new AceFinding
                                {
                                    Triage = LibSnaffle.Classifiers.Rules.Constants.Triage.Red,
                                    FindingReason = "AccessControl on this object grants interesting privileges to a very common low-privilege group or user.",
                                    FindingDetail = ace.Trustee.DisplayName + " was assigned the following rights: " + String.Join(", ", intRights) + "."
                                };
                                aceResult.AceFinding = aceFinding;

                                aclResult.Add(aceResult);
                                break;
                            }
                            else if (trustee.Target && intRights.Count > 0)
                            {
                                SimpleAce aceResult = new SimpleAce
                                {
                                    ACEType = ace.ACEType,
                                    TrusteeSid = ace.TrusteeSid,
                                    TrusteeAlias = ace.TrusteeAlias,
                                    Rights = ace.Rights
                                };
                                AceFinding aceFinding = new AceFinding
                                {
                                    Triage = LibSnaffle.Classifiers.Rules.Constants.Triage.Red,
                                    FindingReason = "AccessControl on this object grants interesting privileges to an explicitly targeted user or group.",
                                    FindingDetail = "By default this targets the current user and any groups they're a member of. Specifically, " + ace.TrusteeAlias + " was assigned the following rights: " + String.Join(", ", intRights) + "."
                                };
                                aceResult.AceFinding = aceFinding;
                                aclResult.Add(aceResult);
                            }
                            else if (trustee.HighPriv)
                            {
                                // boring
                                break;
                            }
                            else if (!trustee.LowPriv)
                            {
                                //non-default, slightly more interesting.
                                SimpleAce aceResult = new SimpleAce
                                {
                                    TrusteeSid = ace.TrusteeSid,
                                    TrusteeAlias = ace.TrusteeAlias,
                                    Rights = ace.Rights
                                };
                                aclResult.Add(aceResult);
                                break;
                            }
                        }
                    }
                }
            }
            return aclResult;
        }
        */
    }   

    public class SimpleAce
    {
        public Trustee Trustee { get; set; }
        public ACEType ACEType { get; set; }
        //public List<SimpleRight> Rights { get; set; }
        public string[] Rights { get; set; }
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
