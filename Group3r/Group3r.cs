using System;

namespace Group3r
{
    public static class Group3r
    {
        /**
         * Summary: Entry point.
         */
        public static void Main(string[] args)
        {
            Console.WriteLine("Debug 1");
            Group3rRunner runner = new Group3rRunner();
            Console.WriteLine("Debug 2");
            runner.Run(args);
        }
    }
}
