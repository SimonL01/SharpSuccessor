namespace SharpSuccessor.Modules
{
    /// <summary>
    /// Strongly-typed container for the parsed command-line arguments. Replaces the
    /// loosely-named (path, name, computer, target) tuple that was passed around before.
    /// </summary>
    internal class Options
    {
        public string Impersonate;  // /impersonate : account to take over (the superseded target)
        public string Path;         // /path        : DN of the OU to create the dMSA under
        public string Account;      // /account     : principal granted read access to the dMSA password
        public string Name;         // /name        : name of the dMSA object to create

        // Optional: operate against a specific DC and/or with explicit credentials
        // so the tool can run from a non-domain-joined context.
        public string Dc;           // /dc
        public string Username;     // /username
        public string Password;     // /password

        // Optional OPSEC: insert a randomized delay between the directory writes so the
        // object-creation (5137) and attribute-modification (5136) events do not land in a
        // tight, easily-correlated cluster. /delay:<min>-<max> (seconds) overrides the range.
        public bool Opsec;
        public int DelayMinSeconds = 30;
        public int DelayMaxSeconds = 180;
    }
}
