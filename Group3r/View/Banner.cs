using System;

namespace BigFish.View
{
    /**
     * Summary: Class for printing the all important ASCII art.
     */
    class Banner
    {
        private static void WriteColor(string textToWrite, ConsoleColor fgColor)
        {
            Console.ForegroundColor = fgColor;

            Console.Write(textToWrite);

            Console.ResetColor();
        }

        private static void WriteColorLine(string textToWrite, ConsoleColor fgColor)
        {
            Console.ForegroundColor = fgColor;

            Console.WriteLine(textToWrite);

            Console.ResetColor();
        }

        public static void PrintBanner()
        {

            string[] barfLines = new[]
            {
                @"  .,-:::::/ :::::::..       ...      ...    :::::::::::::.  .::.   :::::::..  ",
                @",;;-'````'  ;;;;``;;;;   .;;;;;;;.   ;;     ;;; `;;;```.;;;;'`';;, ;;;;``;;;; ",
                @"[[[   [[[[[[/[[[,/[[['  ,[[     \[[,[['     [[[  `]]nnn]]'    .n[[  [[[,/[[[' ",
                @"'$$c.    '$$ $$$$$$c    $$$,     $$$$$      $$$   $$$''      ``'$$$ $$$$$$c   ",
                @" `Y8bo,,,o88o888b '88bo,'888,_ _,88P88    .d888   888o       ,,o888 888b'''8b,",
                @"   `'YMUP'YMMMMMM  'W'   'YMMMMMP'  'YmmMMMM''   YMMMb      YMMP'  MMMM   'WM;",
                @"                                                    github.com/BigFish/BigFish",
                @"                                                            @mikeloss         ",
                @"                                                                              ",
                @"Gaze not into the abyss, lest you become recognized as an abyss domain expert,",
                @"and they expect you keep gazing into the damn thing... - @nickm_tor           "
            };


            ConsoleColor[] patternOne = { ConsoleColor.White, ConsoleColor.Yellow, ConsoleColor.Red, ConsoleColor.Red, ConsoleColor.DarkRed, ConsoleColor.DarkRed, ConsoleColor.White, ConsoleColor.White, ConsoleColor.White, ConsoleColor.White };

            ConsoleColor[] patternTwo =
{
                ConsoleColor.White, ConsoleColor.White, ConsoleColor.White, ConsoleColor.Cyan, ConsoleColor.Blue, ConsoleColor.DarkBlue, ConsoleColor.White, ConsoleColor.White, ConsoleColor.White, ConsoleColor.White
};

            int i = 0;
            foreach (string barfLine in barfLines)
            {
                if (i <= 7)
                {
                    string barfOne = barfLine;
                    WriteColor(barfOne.Substring(0, 59), patternOne[i]);
                    WriteColor(barfOne.Substring(59, 8), patternTwo[i]);
                    WriteColor(barfOne.Substring(67, 11) + "\r\n", patternOne[i]);
                }
                else
                {
                    WriteColorLine(barfLine, ConsoleColor.Green);
                }
                i += 1;
            }

            Console.WriteLine("\r\n");
        }
    }
}
