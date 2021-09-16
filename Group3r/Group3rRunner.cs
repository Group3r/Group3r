using Group3r.Concurrency;
using Group3r.Options;
using Group3r.View;
using LibSnaffle.Concurrency;
using LibSnaffle.Logging;
using NLog.Targets;
using System;
using System.Diagnostics;
using System.Threading.Tasks;

namespace Group3r
{
    /**
     * Summary: Responsible for setting up and running GroupCore.
     */
    class Group3rRunner
    {
        /**
         * Summary: This method is the main controller of the program.
         *          It sets things up and kicks off the threads.
         * Imports: command line args
         * Exports: None
         */
        public void Run(string[] args)
        {
            Banner.PrintBanner();
            GrouperMq mq = new GrouperMq();

            try
            {
                GrouperOptions options = OptionsParser.Parse(args, mq);
                SetupLogger(options.LogToFile, options.LogToConsole, mq, options.LogLevelString, options.LogFilePath);
                GroupCon controller = new GroupCon(options, mq);
                Task groupConThread = Task.Factory.StartNew(() => { controller.Execute(); });
                HandleForever(options, mq);
            }
            catch (Exception e)
            {
                Console.WriteLine("Unhandled exception in Group3rRunner. Please report the following error directly to l0ss or file an issue in GitHub:");
                Console.WriteLine(e.ToString());
                DumpQueue(mq);
                Environment.Exit(1);
            }
        }

        /**
         * Summary: Prints the Mq and exits on fatal error.
         * Imports: BlockingMq reference to the Mq
         * Exports: None
         */
        private void DumpQueue(BlockingMq Mq)
        {
            while (Mq.Q.TryTake(out QueueMessage message))
            {
                // emergency dump of queue contents to console
                Console.WriteLine(message.GetMessage());
            }
            if (Debugger.IsAttached)
            {
                Console.WriteLine("Emergency quit, dumped queue to console, press any key to exit.");
                Console.ReadKey();
            }
            // TODO: exit nicely by returning to calling context.
            Environment.Exit(1);
        }

        /**
         * Summary: Infinite loop to handle Mq messages.
         * Imports: GroupCoreOptions object which gets passed to the processor.
         * Exports: None
         */
        private void HandleForever(GrouperOptions options, GrouperMq mq)
        {
            // TODO: Implement option for output type when required. 
            IMessageProcessor processor = new CliMessageProcessor();

            while (true)
            {
                // mq.Pop blocks.
                QueueMessage msg = mq.Pop();
                processor.ProcessMessage(msg, options);
            }
        }
        /// <summary>
        /// Used to initialise the logger with custom colours.
        /// </summary>
        /// <param name="logToFile"></param>
        /// <param name="mq"></param>
        /// <param name="logLevelString"></param>
        /// <param name="logFilePath"></param>
        private void SetupLogger(bool logToFile, bool logToConsole, BlockingMq mq, string logLevelString, string logFilePath)
        {
            ColoredConsoleTarget logconsole = new ColoredConsoleTarget("logconsole")
            {
                DetectOutputRedirected = true,
                UseDefaultRowHighlightingRules = false,
                WordHighlightingRules = {
                        new ConsoleWordHighlightingRule("[Trace]", ConsoleOutputColor.DarkGray, ConsoleOutputColor.Black),
                        new ConsoleWordHighlightingRule("[Degub]", ConsoleOutputColor.Gray, ConsoleOutputColor.Black),
                        new ConsoleWordHighlightingRule("[Info]", ConsoleOutputColor.White, ConsoleOutputColor.Black),
                        new ConsoleWordHighlightingRule("[Error]", ConsoleOutputColor.Magenta, ConsoleOutputColor.Black),
                        new ConsoleWordHighlightingRule("[Fatal]", ConsoleOutputColor.Red, ConsoleOutputColor.Black),
                        // File result prettifier for snaffler output.
                        new ConsoleWordHighlightingRule("[File]", ConsoleOutputColor.Green, ConsoleOutputColor.Black),
                        new ConsoleWordHighlightingRule("[GPO]", ConsoleOutputColor.Cyan, ConsoleOutputColor.Black),
                        new ConsoleWordHighlightingRule("{Red}", ConsoleOutputColor.Red, ConsoleOutputColor.White),
                        new ConsoleWordHighlightingRule("{Black}", ConsoleOutputColor.DarkGray, ConsoleOutputColor.White),
                        new ConsoleWordHighlightingRule("{Yellow}", ConsoleOutputColor.Yellow, ConsoleOutputColor.White),
                        new ConsoleWordHighlightingRule("{Green}", ConsoleOutputColor.Yellow, ConsoleOutputColor.White),
                        /*
                        // TODO: these rules need to be removed and replaced with something better
                        new ConsoleWordHighlightingRule
                        {
                            CompileRegex = true,
                            Regex = @"^\d\d\d\d-\d\d\-\d\d \d\d:\d\d:\d\d [\+-]\d\d:\d\d ",
                            ForegroundColor = ConsoleOutputColor.DarkGray,
                            BackgroundColor = ConsoleOutputColor.Black
                        },
                        new ConsoleWordHighlightingRule
                        {
                            CompileRegex = true,
                            Regex = @"<.*\|.*\|.*\|.*?>",
                            ForegroundColor = ConsoleOutputColor.Cyan,
                            BackgroundColor = ConsoleOutputColor.Black
                        },
                        new ConsoleWordHighlightingRule
                        {
                            CompileRegex = true,
                            Regex = @"\((?:[^\)]*\)){1}",
                            ForegroundColor = ConsoleOutputColor.DarkMagenta,
                            BackgroundColor = ConsoleOutputColor.Black
                        }
                        */
                    }
            };
            Logging.SetupLogger(logToFile, logToConsole, mq, logLevelString, logFilePath, logconsole);
        }
    }
}
