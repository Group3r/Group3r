using LibSnaffle.Errors;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.AccountManagement;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.AccessControl;
using System.Security.Principal;
using LibSnaffle.Concurrency;

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

        /// <summary>
        /// Specifically targeted domain controller
        /// </summary>
        public string TargetDC { get; set; }

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
            this.Mq = mq;
        }

        /// <summary>
        /// This constructor assumes it's running online and populates fields through enumeration.
        /// </summary>
        /// <remarks>
        /// Selects the first domain controller in the collection provided by ActiveDirectory.Domain.
        /// </remarks>
        /// <param name="context"></param>
        /// <param name="fullCollection"></param>
        public ActiveDirectory(BlockingMq mq, DirectoryContext context, bool fullCollection = false)
        {
            this.Mq = mq;

            try
            {
                Context = context;
                CurrentDomain = Domain.GetDomain(context);
                CurrentForest = CurrentDomain.Forest;
                if (fullCollection == true)
                {
                    EnumerateDomainControllers();
                    EnumerateComputers();
                    EnumerateUsers();
                    ObtainDomainGpos();
                }
            }
            catch (ActiveDirectoryOperationException e)
            {
                throw new ActiveDirectoryException("Unable to load AD", e);
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
                Mq.Trace("Loading SYSVOL by domain " + CurrentDomain.Name);
                Sysvol = helper.LoadSysvolOnlineByDomain(CurrentDomain.Name);
            }
            catch (Exception)
            {
                Mq.Trace("Loading SYSVOL by DC " + DomainControllerIPs[0]);
                Sysvol = helper.LoadSysvolOnlineByDc(CurrentDomain.Name, DomainControllerIPs[0]);
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
        /// Enumerates DCs into the AD object.
        /// </summary>
        /// <returns>
        /// DomainControllerCollection.
        /// </returns>
        public void EnumerateDomainControllers()
        {
            try
            {
                DomainControllers = DomainController.FindAll(Context);
            }
            catch (Exception e)
            {
                throw new ActiveDirectoryException("Something went wrong trying to find domain controllers", e);
            }

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

            Mq.Trace("Testing DC Connectivity");

            List<string> dcs = new List<string>();

            if (TargetDC != null)
            {
                dcs.Add(TargetDC);
            }
            else
            {
                foreach (DomainController domainController in DomainControllers)
                {
                    dcs.Add(domainController.Name);
                }
            }

            foreach (string dc in dcs)
            {
                try
                {
                    Mq.Trace("Trying to enumerate GPOs from " + dc);
                    List<GPO> gpos = EnumerateDomainGposFromDC(dc);
                    try
                    {
                        Mq.Trace("Trying to enumerate Packages from " + dc);
                        EnumerateGpoPackages(dc, gpos);
                    }
                    catch (Exception e)
                    {
                        Mq.Error("Error Obtaining Packages from DC at IP " + dc + " " + e.ToString());
                    }
                    allDomainGpos.AddRange(gpos);

                    // as soon as one of these succeeds we can stop trying
                    break;
                }
                catch (Exception e)
                {
                    Mq.Error("Error Obtaining GPOs from DC at IP " + dc + " " + e.ToString());
                    continue;
                    //throw new ActiveDirectoryException("Error Obtaining GPOs from DC at IP " + dc, e);
                }
            }

            // Ensure we actually got some data.
            if (allDomainGpos.Count == 0)
            {
                throw new ActiveDirectoryException("Something fucked out finding stuff in the domain. You must be holding it wrong.");
            }

            Gpos = allDomainGpos;
            Mq.Trace("Successfully got GPOs.");
        }

        /// <summary>
        /// Queries a DCS via LDAP and downloads GPOs.
        /// </summary>
        /// <param name="domainController">The IP of the DC.</param>
        /// <returns></returns>
        private List<GPO> EnumerateDomainGposFromDC(string domainController)
        {
            // TODO add support for user defined creds here.
            List<GPO> domainGpos = new List<GPO>();
            using (DirectoryEntry entry = new DirectoryEntry("LDAP://" + domainController))
            {
                using (DirectorySearcher mySearcher = new DirectorySearcher(entry))
                {

                    mySearcher.Filter = "(objectClass=groupPolicyContainer)";
                    mySearcher.SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner;
                    mySearcher.PropertiesToLoad.Add("adspath");
                    mySearcher.PropertiesToLoad.Add("displayname");
                    mySearcher.PropertiesToLoad.Add("whencreated");
                    mySearcher.PropertiesToLoad.Add("ntsecuritydescriptor");
                    mySearcher.PropertiesToLoad.Add("whenchanged");
                    mySearcher.PropertiesToLoad.Add("cn");
                    mySearcher.PropertiesToLoad.Add("distinguishedname");
                    mySearcher.PropertiesToLoad.Add("name");
                    mySearcher.PropertiesToLoad.Add("versionnumber");
                    mySearcher.PropertiesToLoad.Add("flags");

                    // No size limit, reads all objects
                    mySearcher.SizeLimit = 0;

                    // Read data in pages of 250 objects. Make sure this value is below the limit configured in your AD domain (if there is a limit)
                    mySearcher.PageSize = 250;

                    SearchResultCollection searchResultCollection = mySearcher.FindAll();

                    Mq.Trace(searchResultCollection.Count.ToString() + " GPOs found. Grabbing their attributes.");

                    int i = 0;
                    foreach (SearchResult resEnt in searchResultCollection)
                    {
                        i++;
                        Mq.Trace("Grabbing attributes for GPO #" + i.ToString());
                        // Note: Properties can contain multiple values.
                        string thisuid = resEnt.Properties["name"][0].ToString();
                        GPO gpo = new GPO(thisuid);

                        gpo.Attributes.AdsPath = resEnt.Properties["adspath"][0].ToString();
                        gpo.Attributes.DisplayName = resEnt.Properties["displayname"][0].ToString();
                        gpo.Attributes.CreatedDate = (DateTime) (resEnt.Properties["whenCreated"][0]);
                        gpo.Attributes.ModifiedDate = (DateTime) (resEnt.Properties["whenChanged"][0]);
                        //string ntSecurityDescriptorString = resEnt.Properties["ntsecuritydescriptor"][0].ToString();
                        byte[] ntSecurityDescriptor = (byte[])resEnt.Properties["ntsecuritydescriptor"][0];
                        RawSecurityDescriptor rawSecurityDescriptor = new RawSecurityDescriptor(ntSecurityDescriptor, 0);

                        string ntSecurityDescriptorString = rawSecurityDescriptor.GetSddlForm(AccessControlSections.All);
                        gpo.Attributes.NtSecurityDescriptor = ntSecurityDescriptorString;

                        Sddl.Parser.Sddl parsedSddl = new Sddl.Parser.Sddl(ntSecurityDescriptorString, Sddl.Parser.SecurableObjectType.DirectoryServiceObject);
                        gpo.Attributes.NtSecurityDescriptorSddl = parsedSddl;

                        gpo.Attributes.Uid = resEnt.Properties["name"][0].ToString();
                        gpo.Attributes.VersionNumber = resEnt.Properties["versionnumber"][0].ToString();
                        //gpo.Attributes.Cn = resEnt.Properties["cn"][0].ToString();
                        gpo.Attributes.DistinguishedName = resEnt.Properties["distinguishedname"][0].ToString();

                        string gpoFlags = resEnt.Properties["flags"][0].ToString();
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
                }
                Mq.Trace("Finished grabbing GPO attributes.");
                return domainGpos;
            }
        }

        /// <summary>
        /// Queries the domain via LDAP and returns a list of computer names as strings.
        /// </summary>
        /// https://stackoverflow.com/questions/1605567/list-all-computers-in-active-directory
        /// <remarks>
        /// </remarks>
        /// <param name="domain"></param>
        /// <returns></returns>
        public void EnumerateComputers()
        {
            List<string> ComputerNames = new List<string>();

            DirectoryEntry entry = new DirectoryEntry($"LDAP://{CurrentDomain.Name}");
            DirectorySearcher mySearcher = new DirectorySearcher(entry);
            mySearcher.Filter = ("(objectClass=computer)");
            mySearcher.SizeLimit = int.MaxValue;
            mySearcher.PageSize = int.MaxValue;

            foreach (SearchResult resEnt in mySearcher.FindAll())
            {
                //"CN=SGSVG007DC"
                string ComputerName = resEnt.GetDirectoryEntry().Name;
                if (ComputerName.StartsWith("CN="))
                {
                    ComputerName = ComputerName.Remove(0, "CN=".Length);
                }
                ComputerNames.Add(ComputerName);
            }

            mySearcher.Dispose();
            entry.Dispose();

            this.Computers = ComputerNames;
        }

        public void EnumerateUsers()
        {
            List<string> users = new List<string>();

            using (var context = new PrincipalContext(ContextType.Domain, CurrentDomain.Name))
            {
                using (var searcher = new PrincipalSearcher(new UserPrincipal(context)))
                {
                    foreach (var result in searcher.FindAll())
                    {
                        try
                        {
                            DirectoryEntry de = result.GetUnderlyingObject() as DirectoryEntry;
                            users.Add(de.Properties["samAccountName"].Value.ToString());
                        }
                        catch { }
                    }
                }
            }

            this.Users = users;
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
        /// <param name="domainController"></param>
        /// <param name="gpos"></param>
        private void EnumerateGpoPackages(string domainController, List<GPO> gpos)
        {
            using (DirectorySearcher packageSearcher =
                new DirectorySearcher("LDAP://" + domainController + "/System/Policies"))
            {
                // this bit c/o @grouppolicyguy, thanks Darren!
                packageSearcher.Filter = "(objectClass=packageRegistration)";
                packageSearcher.PropertiesToLoad.Add("displayName");
                packageSearcher.PropertiesToLoad.Add("distinguishedName");
                packageSearcher.PropertiesToLoad.Add("msiFileList");
                packageSearcher.PropertiesToLoad.Add("msiScriptName");
                packageSearcher.PropertiesToLoad.Add("productCode");
                packageSearcher.PropertiesToLoad.Add("whenCreated");
                packageSearcher.PropertiesToLoad.Add("whenChanged");
                packageSearcher.PropertiesToLoad.Add("upgradeProductCode");
                packageSearcher.PropertiesToLoad.Add("cn");

                SearchResultCollection foundPackages = packageSearcher.FindAll();

                if (foundPackages.Count > 0)
                {
                    //iterate through the apps found
                    foreach (SearchResult package in foundPackages)
                    {
                        try
                        {
                            PackageSetting gpoPackage = new PackageSetting();
                            // do stuff to put the right shit in the gpopackage.

                            gpoPackage.DisplayName = package.Properties["displayName"][0].ToString();

                            //check to see if there are transforms
                            if (package.Properties["msiFileList"].Count > 1)
                            {
                                for (int i = 0; i < package.Properties["msiFileList"].Count; i++)
                                {
                                    string[] splitPath = package.Properties["msiFileList"][i].ToString()
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
                                gpoPackage.MsiFileList.Add(package.Properties["msiFileList"][0].ToString()
                                    .TrimStart(new char[] { '0', ':' }));
                            }

                            //the product code is a byte array, so we need to get the enum on it and iterate through the collection
                            ResultPropertyValueCollection colProductCode = package.Properties["productCode"];
                            byte[] productCodeBytes = (byte[])colProductCode[0];
                            Guid productCodeGuid = new Guid(productCodeBytes);
                            gpoPackage.ProductCode = productCodeGuid;
                            // and again for the upgradeCode
                            ResultPropertyValueCollection colUpgradeCode = package.Properties["upgradeProductCode"];
                            byte[] upgradeCodeBytes = (byte[])colUpgradeCode[0];
                            Guid upgradeCodeGuid = new Guid(upgradeCodeBytes);
                            gpoPackage.UpgradeProductCode = upgradeCodeGuid;

                            //now do the whenChanged and whenCreated stuff
                            gpoPackage.CreatedDate = (DateTime)(package.Properties["whenCreated"][0]);
                            gpoPackage.CreatedDate = (DateTime)(package.Properties["whenChanged"][0]);

                            //Next we need to find the GPO this app is in
                            string DN = package.Properties["adsPath"][0].ToString();
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
                            DirectoryEntry GPOPath = new DirectoryEntry(FQDN);
                            gpoPackage.ParentGpo = GPOPath.Properties["Name"][0].ToString();

                            //now resolve whether the app is published or assigned
                            if (arrFQDN[3] == "CN=User")
                            {
                                if (package.Properties["msiScriptName"][0].ToString() == "A")
                                    gpoPackage.PackageAction = "User Assigned";
                                if (package.Properties["msiScriptName"][0].ToString() == "P")
                                    gpoPackage.PackageAction = "User Published";
                                if (package.Properties["msiScriptName"][0].ToString() == "R")
                                    gpoPackage.PackageAction = "Package Removed";
                            }
                            else if (package.Properties["msiScriptName"][0].ToString() == "R")
                                gpoPackage.PackageAction = "Package Removed";
                            else
                                gpoPackage.PackageAction = "Computer Assigned";

                            gpoPackage.Cn = package.Properties["cn"].ToString();
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
            }
        }

        public List<string> GetUsersGroupsAllDomains(string username)
        {
            UserPrincipal foundUser = UserPrincipal.FindByIdentity(new PrincipalContext(ContextType.Domain, CurrentDomain.Name), IdentityType.SamAccountName, username);

            if (foundUser != null)
            {
                try
                {
                    DirectoryEntry de = foundUser.GetUnderlyingObject() as DirectoryEntry;

                    var groups = new List<string>();

                    de.RefreshCache(new[] { "canonicalName", "objectSid", "distinguishedName" });

                    var userCn = (string)de.Properties["canonicalName"].Value;
                    var domainDns = userCn.Substring(0, userCn.IndexOf("/", StringComparison.Ordinal));

                    var d = Domain.GetDomain(new DirectoryContext(DirectoryContextType.Domain, domainDns));
                    var searchedDomains = new List<string>();

                    //search domains in the same forest (this will include the user's domain)
                    var userDn = (string)de.Properties["distinguishedName"].Value;
                    foreach (Domain domain in d.Forest.Domains)
                    {
                        searchedDomains.Add(domain.Name);
                        var ds = new DirectorySearcher
                        {
                            SearchRoot = new DirectoryEntry($"LDAP://{domain.Name}"),
                            Filter = $"(&(objectclass=group)(member={userDn}))"
                        };
                        ds.PropertiesToLoad.Add("msDS-PrincipalName");
                        using (var results = ds.FindAll())
                        {
                            foreach (SearchResult result in results)
                            {
                                groups.Add((string)result.Properties["msDS-PrincipalName"][0]);
                            }
                        }
                    }

                    //search any externally trusted domains
                    var trusts = d.GetAllTrustRelationships();
                    if (trusts.Count == 0) return groups;

                    var userSid = new SecurityIdentifier((byte[])de.Properties["objectSid"].Value, 0).ToString();
                    foreach (TrustRelationshipInformation trust in trusts)
                    {
                        //ignore domains in the same forest that we already searched, or outbound trusts
                        if (searchedDomains.Contains(trust.TargetName)
                            || trust.TrustDirection == TrustDirection.Outbound) continue;
                        var domain = new DirectoryEntry($"LDAP://{trust.TargetName}");
                        domain.RefreshCache(new[] { "distinguishedName" });
                        var domainDn = (string)domain.Properties["distinguishedName"].Value;

                        //construct the DN of what the foreign security principal object would be
                        var fsp = $"CN={userSid},CN=ForeignSecurityPrincipals,{domainDn}";

                        var ds = new DirectorySearcher
                        {
                            SearchRoot = domain,
                            Filter = $"(&(objectclass=group)(member={fsp}))"
                        };
                        ds.PropertiesToLoad.Add("msDS-PrincipalName");
                        using (var results = ds.FindAll())
                        {
                            foreach (SearchResult result in results)
                            {
                                groups.Add((string)result.Properties["msDS-PrincipalName"][0]);
                            }
                        }
                    }
                    return groups;
                }

                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
            }
            return new List<string>();
        }

    }
}
