using LibSnaffle.ActiveDirectory.LDAP;
using LibSnaffle.Concurrency;
using LibSnaffle.Errors;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.AccessControl;

namespace LibSnaffle.ActiveDirectory
{
    /// <summary>
    /// Represents an Active Directory, containing the elements that are useful for enumeration. Currently only stores one domain.
    /// </summary>
    /// <remarks>
    /// 
    /// TODO: Users, computers etc if we want to?
    /// </remarks>
    public class ActiveDirectory
    {
        public BlockingMq Mq { get; set; }

        /// <summary>
        /// Stores the current AD Forest.
        /// </summary>
        public Forest CurrentForest { get; set; }

        /// <summary>
        /// Stores Other Domains in current Forest
        /// </summary>
        public DomainCollection CurrentForestDomains { get; set; }

        /// <summary>
        /// Stores the current AD Domain.
        /// </summary>
        public Domain CurrentDomain { get; set; }

        /// <summary>
        /// Stores the DirectoryContext.
        /// </summary>
        public DirectoryContext Context { get; set; }

        public PrincipalContext PContext { get; set; }
        /// <summary>
        /// Stores the Sysvol.
        /// </summary>
        public Sysvol Sysvol { get; set; }

        /// <summary>
        /// Stores a list of GPO objects.
        /// </summary>
        public List<GPO> Gpos { get; set; }

        /// <summary>
        /// Stores a DomainControllerCollection of all DCs in the domain.
        /// </summary>
        public DomainControllerCollection DomainControllers { get; set; }
        public List<String> DomainControllerNames { get; set; } = new List<string>();

        /// <summary>
        /// Specifically targeted domain controller
        /// </summary>
        public string TargetDC { get; set; }
        public string TargetDomain { get; set; }

        /// <summary>
        /// Stores a List of all DC IPs in the domain.
        /// </summary>
        public List<string> DomainControllerIPs { get; set; } = new List<string>();
        /// <summary>
        /// All users in the AD domain and local machine.
        /// </summary>
        public List<string> Users { get; set; }

        /// <summary>
        /// All computers in the AD domain.
        /// </summary>
        public List<string> Computers { get; set; }

        /// <summary>
        /// Default constructor leaving all fields unassigned.
        /// </summary>
        public ActiveDirectory(BlockingMq mq)
        {
            Mq = mq;
        }

        public DirectorySearch DirectorySearch { get; set; }

        /// <summary>
        /// This constructor assumes it's running online and populates fields through enumeration.
        /// </summary>
        public ActiveDirectory(BlockingMq mq, string targetDomain = null, string targetDc = null)
        {
            Mq = mq;
            TargetDC = targetDc;
            TargetDomain = targetDomain;

            try
            {
                DirectorySearch = GetDirectorySearch();
            }
            catch (ActiveDirectoryOperationException e)
            {
                throw new ActiveDirectoryException("Unable to talk to AD. ", e);
            }
        }

        private DirectorySearch GetDirectorySearch()
        {
            try
            {
                // target domain and dc set
                if ((!string.IsNullOrEmpty(TargetDomain)) && (!string.IsNullOrEmpty(TargetDC)))
                {
                    Mq.Trace("Target DC and Domain specified: " + TargetDomain + " + " + TargetDC);
                }
                // no target DC or domain set
                else
                {
                    Mq.Trace("Getting current domain from user context.");
                    CurrentDomain = Domain.GetCurrentDomain();
                    TargetDomain = CurrentDomain.Name;
                    TargetDC = TargetDomain;
                }

                return new DirectorySearch(TargetDomain, TargetDC);

            }
            // TODO: tidy up generic exception.
            catch (Exception e)
            {
                throw new ActiveDirectoryException("Problem figuring out DirectoryContext and/or DCs, you might need to fix your DNS, or define manually with -d and/or -c.", e);
            }
        }


        /// <summary>
        /// Loads a Sysvol over the network.
        /// </summary>
        /// <remarks>
        /// Tries to load via the domain name first, then if that fails, the domain controller.
        /// </remarks>
        /// <param name="helper">SysvolHelper to do the loading.</param>
        public void LoadSysvolOnline(SysvolHelper helper)
        {
            try
            {
                Mq.Degub("Loading SYSVOL by domain " + TargetDomain);
                Sysvol = helper.LoadSysvolOnlineByDomain(TargetDomain);
                Mq.Degub("Finished loading SYSVOL");
            }
            catch (Exception e)
            {
                Mq.Degub("Loading SYSVOL by DC " + TargetDC);
                Sysvol = helper.LoadSysvolOnlineByDc(TargetDomain, TargetDC);
                Mq.Degub("Finished loading SYSVOL");
            }
        }

        /// <summary>
        /// Enumerate all domains in the current forest.
        /// </summary>
        /// <param name="CurrentForest">The current forest</param>
        /// <returns>List of Domains.</returns>
        public void EnumerateDomains(Forest CurrentForest)
        {
            CurrentForestDomains = CurrentForest.Domains;
        }

        /// <summary>
        /// Iterates over each DC trying to pull GPOs until it finds one that works, then stops.
        /// </summary>
        /// <param name="dcs">Collection of DCs</param>
        /// <returns>
        /// List of GPOs from the domain.
        /// </returns>
        public void ObtainDomainGpos()
        {
            List<GPO> allDomainGpos = new List<GPO>();

            try
            {
                Mq.Trace("Trying to enumerate GPOs from " + TargetDC);
                List<GPO> gpos = EnumerateDomainGposFromDC();
                try
                {
                    Mq.Trace("Trying to enumerate Packages from " + TargetDC);
                    EnumerateGpoPackages(gpos);
                }
                catch (Exception e)
                {
                    Mq.Error("Error Obtaining Packages from DC " + TargetDC + " " + e.ToString());
                }
                // TODO move package enumeration to work more like link enumeration does

                allDomainGpos.AddRange(gpos);

                Gpos = allDomainGpos;
                try
                {
                    EnumerateDomainGpoLinks();
                }
                catch (Exception e)
                {
                    Mq.Error("Failed to enumerate domain GPO links.");
                    Mq.Trace(e.ToString());
                }
            }
            catch (Exception e)
            {
                Mq.Error("Error Obtaining GPOs from DC " + TargetDC + " " + e.ToString());
            }


            // Ensure we actually got some data.
            if (Gpos.Count == 0)
            {
                throw new ActiveDirectoryException("Something fucked out finding stuff in the domain. You must be holding it wrong.");
            }

            Mq.Trace("Successfully got GPO data.");
        }

        private void EnumerateDomainGpoLinks()
        {

            var ldapProperties = new string[] { "gplink", "gpoptions", "name", "displayname" };

            string ldapFilter = "(|(objectClass=organizationalUnit)(objectClass=site)(objectClass=domain))";

            // UH OH we might need to fix the naming context thing

            IEnumerable<SearchResultEntry> searchResultEntries = DirectorySearch.QueryLdap(ldapFilter, ldapProperties, System.DirectoryServices.Protocols.SearchScope.Subtree);

            int count = searchResultEntries.Count();

            Mq.Trace(count.ToString() + " sites and OUs found.");

            Dictionary<string, List<string>> gpoLinks = new Dictionary<string, List<string>>();

            if (count >= 1)
            {
                foreach (SearchResultEntry searchResultEntry in searchResultEntries)
                {
                    try
                    {
                        //Mq.Degub("This is where the horrible GPO link bug happens...");
                        //string adspath = searchResultEntry.Path;

                        string linkedGpos = searchResultEntry.GetProperty("gplink");

                        if (!string.IsNullOrWhiteSpace(linkedGpos))
                        {

                            var splitGpos = linkedGpos.Split(']', '[');

                            foreach (string gpolink in splitGpos)
                            {
                                if (gpolink.StartsWith("LDAP"))
                                {
                                    GPOLink gpoLinkResult = new GPOLink();
                                    //Split the GPLink value. The distinguishedname will be in the first part, and the status of the gplink in the second
                                    var splitLink = gpolink.Split(';');
                                    var distinguishedName = splitLink[0];
                                    distinguishedName =
                                        distinguishedName.Substring(distinguishedName.IndexOf("CN=",
                                            StringComparison.OrdinalIgnoreCase));
                                    gpoLinkResult.LinkPath = searchResultEntry.DistinguishedName;
                               
                                    var status = splitLink[1];

                                    switch (status)
                                    {
                                        case "0":
                                            gpoLinkResult.LinkEnforced = "Enabled, Unenforced";
                                            break;
                                        case "1":
                                            gpoLinkResult.LinkEnforced = "Disabled, Unenforced";
                                            break;
                                        case "2":
                                            gpoLinkResult.LinkEnforced = "Disabled, Enforced";
                                            break;
                                        case "3":
                                            gpoLinkResult.LinkEnforced = "Enabled, Enforced";
                                            break;
                                    }

                                    //gpoLinkResult.LinkPath = adspath;

                                    //Mq.Degub("Or maybe this is where it went wrong...");
                                    try
                                    {
                                        GPO gpo = Gpos.Where(g =>
                                            g.Attributes.DistinguishedName.Equals(distinguishedName,
                                                StringComparison.OrdinalIgnoreCase)).First();
                                        gpo.Attributes.GpoLinks.Add(gpoLinkResult);
                                        //Mq.Degub("gpo selection went ok...");
                                    }
                                    catch (Exception e)
                                    {
                                        Mq.Error("Error looking up GPO " + distinguishedName + " to insert links in it.");
                                    }
                                }
                                else
                                {
                                    if (!String.IsNullOrWhiteSpace(gpolink))
                                    {
                                        Mq.Error("Unparsed GPO Link:" + gpolink);
                                    }
                                }
                            }
                        }
                        else
                        {
                            //Mq.Trace("No GPO Links found in " + searchResultEntry.DistinguishedName);
                        }
                    }
                    catch (Exception e)
                    {
                        Mq.Error("Something went wrong inserting GPO links into the GPO objects." + e.ToString());
                    }
                }
            }
        }
        /// <summary>
        /// Queries a DCS via LDAP and downloads GPOs.
        /// </summary>
        /// <param name="domainController">The IP of the DC.</param>
        /// <returns></returns>
        private List<GPO> EnumerateDomainGposFromDC()
        {
            List<GPO> domainGpos = new List<GPO>();

            var ldapProperties = new string[]
            {
            "adspath",
            "displayname",
            "whencreated",
            "ntsecuritydescriptor",
            "whenchanged",
            "cn",
            "distinguishedname",
            "name",
            "versionnumber",
            "flags"
            };

            string ldapFilter = "(objectClass=groupPolicyContainer)";

            IEnumerable<SearchResultEntry> searchResultEntries = DirectorySearch.QueryLdap(ldapFilter, ldapProperties, System.DirectoryServices.Protocols.SearchScope.Subtree);

            int count = searchResultEntries.Count();

            Mq.Trace(count.ToString() + " GPOs found.");

            int i = 0;
            foreach (SearchResultEntry resEnt in searchResultEntries)
            {
                i++;
                Mq.Trace("Ingesting attributes for GPO #" + i.ToString());
                // Note: Properties can contain multiple values.
                string thisuid = resEnt.GetProperty("name");
                GPO gpo = new GPO(thisuid);

                gpo.Attributes.AdsPath = resEnt.GetProperty("adspath");
                gpo.Attributes.DisplayName = resEnt.GetProperty("displayname");

                string createdDate = resEnt.GetProperty("whenCreated");
                string modifiedDate = resEnt.GetProperty("whenChanged");

                gpo.Attributes.CreatedDate = DateTime.ParseExact(createdDate, "yyyyMMddHHmmss.0K", CultureInfo.InvariantCulture);
                gpo.Attributes.ModifiedDate = DateTime.ParseExact(modifiedDate, "yyyyMMddHHmmss.0K", CultureInfo.InvariantCulture);
                byte[] ntSecurityDescriptor = resEnt.GetPropertyAsBytes("ntsecuritydescriptor");
                RawSecurityDescriptor rawSecurityDescriptor = new RawSecurityDescriptor(ntSecurityDescriptor, 0);

                string ntSecurityDescriptorString = rawSecurityDescriptor.GetSddlForm(AccessControlSections.All);
                gpo.Attributes.NtSecurityDescriptor = ntSecurityDescriptorString;

                Sddl.Parser.Sddl parsedSddl = new Sddl.Parser.Sddl(ntSecurityDescriptorString, Sddl.Parser.SecurableObjectType.DirectoryServiceObject);
                gpo.Attributes.NtSecurityDescriptorSddl = parsedSddl;

                gpo.Attributes.Uid = resEnt.GetProperty("name");
                gpo.Attributes.VersionNumber = resEnt.GetProperty("versionnumber");
                //gpo.Attributes.Cn = resEnt.Properties["cn"][0].ToString();
                gpo.Attributes.DistinguishedName = resEnt.GetProperty("distinguishedname");

                string gpoFlags = resEnt.GetProperty("flags");
                switch (gpoFlags)
                {
                    case "0":
                        gpo.Attributes.UserPolicyEnabled = true;
                        gpo.Attributes.ComputerPolicyEnabled = true;
                        break;
                    case "1":
                        gpo.Attributes.ComputerPolicyEnabled = true;
                        gpo.Attributes.UserPolicyEnabled = false;
                        break;
                    case "2":
                        gpo.Attributes.ComputerPolicyEnabled = false;
                        gpo.Attributes.UserPolicyEnabled = true;
                        break;
                    case "3":
                        gpo.Attributes.ComputerPolicyEnabled = false;
                        gpo.Attributes.UserPolicyEnabled = false;
                        break;
                    default:
                        Mq.Degub("Couldn't process GPO Enabled Status. Weird.");
                        break;
                }
                domainGpos.Add(gpo);
            }
            Mq.Trace("Finished grabbing GPO attributes.");
            return domainGpos;
        }

        /// <summary>
        /// Consolidates GPOs enumerated from a DC and SYSVOL.
        /// </summary>
        /// <remarks>
        /// Iterates over each GPO in Sysvol. If the GPO already exists in the domainGPOS, add a ref to the Sysvol directory. If not, add it to the list.
        /// </remarks>
        public void ConsolidateGpos()
        {
            foreach (GPO gpo in Sysvol.Gpos)
            {
                string dirUid = Path.GetFileName(gpo.Attributes.PathInSysvol);
                int index = Gpos.FindIndex(g => string.Equals(g.Attributes.Uid, dirUid));
                if (index < 0)
                {
                    Gpos.Add(gpo);
                }
                else
                {
                    Gpos[index].Attributes.PathInSysvol = gpo.Attributes.PathInSysvol;
                    foreach (GpoSetting setting in gpo.Settings)
                    {
                        Gpos[index].Settings.Add(setting);
                    }
                    Gpos[index].GpoFiles = gpo.GpoFiles;
                }
            }
        }

        /// <summary>
        /// Pulls info about Packages from AD
        /// </summary>
        /// <param name="gpos"></param>
        private void EnumerateGpoPackages(List<GPO> gpos)
        {
            var ldapProperties = new string[]
            { "displayName",
                "adsPath",
                "distinguishedName",
                "msiFileList",
                "msiScriptName",
                "productCode",
                "whenCreated",
                "whenChanged",
                "upgradeProductCode",
                "cn"};

            string ldapFilter = "(objectClass=packageRegistration)";

            IEnumerable<SearchResultEntry> searchResultEntries = DirectorySearch.QueryLdap(ldapFilter, ldapProperties, System.DirectoryServices.Protocols.SearchScope.Subtree);

            int count = searchResultEntries.Count();

            //iterate through the apps found
            foreach (SearchResultEntry package in searchResultEntries)
            {
                try
                {
                    PackageSetting gpoPackage = new PackageSetting
                    {
                        Source = "LDAP",
                        // do stuff to put the right shit in the gpopackage.

                        DisplayName = package.GetProperty("displayName")
                    };

                    //check to see if there are transforms
                    string[] msiFileList = package.GetPropertyAsArray("msiFileList");

                    int msiFileCount = msiFileList.Count();
                    if (msiFileCount > 1)
                    {
                        for (int i = 0; i < msiFileCount; i++)
                        {
                            string[] splitPath = msiFileList[i].ToString()
                                .Split(new Char[] { ':' });
                            foreach (string path in splitPath)
                            {
                                if (path == "0")
                                {
                                    continue;
                                }
                                else
                                {
                                    gpoPackage.MsiFileList.Add(path);
                                }
                            }
                        }
                    }
                    else
                    {
                        gpoPackage.MsiFileList.Add(msiFileList[0].ToString()
                            .TrimStart(new char[] { '0', ':' }));
                    }

                    byte[] productCodeBytes = package.GetPropertyAsBytes("productCode");
                    Guid productCodeGuid = new Guid(productCodeBytes);
                    gpoPackage.ProductCode = productCodeGuid;
                    // and again for the upgradeCode
                    byte[] upgradeCodeBytes = package.GetPropertyAsBytes("upgradeProductCode");
                    Guid upgradeCodeGuid = new Guid(upgradeCodeBytes);
                    gpoPackage.UpgradeProductCode = upgradeCodeGuid;

                    //now do the whenChanged and whenCreated stuff

                    string createdDate = package.GetProperty("whenCreated");
                    string modifiedDate = package.GetProperty("whenChanged");

                    gpoPackage.CreatedDate = DateTime.ParseExact(createdDate, "yyyyMMddHHmmss.0K", CultureInfo.InvariantCulture); ;
                    gpoPackage.ModifiedDate = DateTime.ParseExact(modifiedDate, "yyyyMMddHHmmss.0K", CultureInfo.InvariantCulture); ;

                    //Next we need to find the GPO this app is in
                    string DN = package.DistinguishedName;
                    string[] arrFQDN = DN.Split(new Char[] { ',' });
                    string FQDN = "";
                    for (int i = 0; i != arrFQDN.Length; i++)
                    {
                        if (i > 3)
                        {
                            //if its the first one, don't put a comma in front of it
                            if (i == 4)
                                FQDN = arrFQDN[i];
                            else
                                FQDN = FQDN + "," + arrFQDN[i];
                        }
                    }

                    FQDN = "LDAP://" + FQDN;
                    try
                    {
                        DirectoryEntry GPOPath = new DirectoryEntry(FQDN);
                        gpoPackage.ParentGpo = GPOPath.Properties["Name"][0].ToString();
                    }
                    catch (Exception e)
                    {
                        Mq.Error("That one thing with DirectoryEntry creation broke in the package enum method.");
                    }

                    //now resolve whether the app is published or assigned
                    if (arrFQDN[3] == "CN=User")
                    {
                        if (package.GetProperty("msiScriptName") == "A")
                            gpoPackage.PackageAction = "User Assigned";
                        if (package.GetProperty("msiScriptName") == "P")
                            gpoPackage.PackageAction = "User Published";
                        if (package.GetProperty("msiScriptName") == "R")
                            gpoPackage.PackageAction = "Package Removed";
                    }
                    else
                        gpoPackage.PackageAction = "Computer Assigned";


                    gpoPackage.Cn = package.GetProperty("cn");
                    // add the package directly into its parent GPO
                    gpoPackage.PolicyType = PolicyType.Package;

                    gpos.SingleOrDefault(p => p.Attributes.Uid == gpoPackage.ParentGpo).Settings.Add(gpoPackage);
                }
                catch (Exception e)
                {
                    throw new ActiveDirectoryException("Error setting GPO packages", e);
                }
            }
        }

        public List<Trustee> GetUsersGroupsRecursive(string domainUser)
        {
            List<Trustee> results = new List<Trustee>();
            // get user's distinguishedName
            string userFilter = "(&(objectCategory=user)(objectClass=user)(|(userPrincipalName={0})(cn=" + domainUser + ")))";
            var ldapProperties = new string[] { "distinguishedName", "objectsid", "cn" };
            IEnumerable<SearchResultEntry> userSearchResultEntries = DirectorySearch.QueryLdap(userFilter, ldapProperties, System.DirectoryServices.Protocols.SearchScope.Subtree);

            // check we got something
            if (userSearchResultEntries.Count() > 0)
            {
                SearchResultEntry userDn = userSearchResultEntries.First();
                // get user's direct group memberships
                string groupFilter = "(&(objectClass=group)(member=" + userDn.GetProperty("distinguishedName") + "))";
                // stick user in result list
                results.Add(new Trustee() { DistinguishedName = userDn.DistinguishedName, Sid = userDn.GetSid(), DisplayName = userDn.GetProperty("cn") });
                IEnumerable<SearchResultEntry> groupSearchResultEntries = DirectorySearch.QueryLdap(groupFilter, ldapProperties, System.DirectoryServices.Protocols.SearchScope.Subtree);

                ConcurrentBag<Trustee> workingGroups = new ConcurrentBag<Trustee>();
                //add first round results into bag and list
                foreach (SearchResultEntry srcGroup in groupSearchResultEntries)
                {
                    Trustee groupDn = new Trustee() { DistinguishedName = srcGroup.DistinguishedName, DisplayName = srcGroup.GetProperty("cn"), Sid = srcGroup.GetSid() };
                    Mq.Degub("Added " + groupDn + " to Target Trustees");
                    workingGroups.Add(groupDn);
                    results.Add(groupDn);
                }
                // iterate while bag is not empty
                while (!workingGroups.IsEmpty)
                {
                    Trustee subGroupDn;
                    // grab one from the working bag
                    workingGroups.TryTake(out subGroupDn);
                    // find the groups it's a member of
                    string subGroupFilter = "(&(objectClass=group)(member=" + subGroupDn.DistinguishedName + "))";
                    IEnumerable<SearchResultEntry> subGroupSearchResultEntries = DirectorySearch.QueryLdap(subGroupFilter, ldapProperties, System.DirectoryServices.Protocols.SearchScope.Subtree);

                    foreach (SearchResultEntry srcGroup in subGroupSearchResultEntries)
                    {
                        string nextGroupDn = srcGroup.DistinguishedName;
                        // if we don't already have them, add them to working and result vars.
                        IEnumerable<Trustee> matches = results.Where(group => group.DistinguishedName == nextGroupDn);
                        if (!matches.Any())
                        {
                            Mq.Degub("Added " + nextGroupDn + " to Target Trustees");

                            workingGroups.Add(new Trustee() { DistinguishedName = srcGroup.DistinguishedName, DisplayName = srcGroup.GetProperty("cn"), Sid = srcGroup.GetSid() });
                            results.Add(new Trustee() { DistinguishedName = srcGroup.DistinguishedName, DisplayName = srcGroup.GetProperty("cn"), Sid = srcGroup.GetSid() });
                        }
                    }
                }
                return results;
            }
            else
            {
                Mq.Error("Failed to find target user in domain, ACL checks are likely to be inaccurate.");
                return new List<Trustee>() { new Trustee() { DisplayName = domainUser, Sid = "" } };
            }
        }
    }
}


