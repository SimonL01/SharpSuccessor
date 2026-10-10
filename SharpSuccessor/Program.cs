using System;

namespace SharpSuccessor
{
    internal class Program
    {
        private const string Banner =
@"   _____ _                      _____
  / ____| |                    / ____|
 | (___ | |__   __ _ _ __ _ __| (___  _   _  ___ ___ ___  ___ ___  ___  _ __
  \___ \| '_ \ / _` | '__| '_ \\___ \| | | |/ __/ __/ _ \/ __/ __|/ _ \| '__|
  ____) | | | | (_| | |  | |_) |___) | |_| | (_| (_|  __/\__ \__ \ (_) | |
 |_____/|_| |_|\__,_|_|  | .__/_____/ \__,_|\___\___\___||___/___/\___/|_|
                         | |
                         |_|
@_logangoins, @SimonL01
";

        static int Main(string[] args)
        {
            Console.WriteLine(Banner);
            try
            {
                return Modules.ArgParse.Execute(args);
            }
            catch (Exception e)
            {
                Console.WriteLine("[!] Exception: " + e.Message);
                return 1;
            }
        }
    }
}
