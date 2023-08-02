using BigFish.Options;
using LibSnaffle.Concurrency;
using NLog;
using System;
using System.Diagnostics;

namespace BigFish.View
{
    /**
     * Summary: Implementation of IMessageProcessor which prints to stdout/stderr via Nlog.
     */
    class CliMessageProcessor : IMessageProcessor
    {
        private readonly Logger Logger;

        /**
         * Summary: constructor
         * Arguments: string containing the control flag for the outputter factory.
         * Returns: CliMessageProcessor instance
         */
        public CliMessageProcessor()
        {
            Logger = LogManager.GetCurrentClassLogger();
        }

        /**
         * Summary: Implementation of ProcessMessage which sends strings to a logger.
         * TODO: Inspecting the type of an instance created via the template
         * pattern to decide behaviour is not awesome. Probaly should do a better thing.
         * Arguments: BigFishMessage containing the message from the queue, GroupCoreOptions for config options
         * Returns: None
         */
        public bool ProcessMessage(QueueMessage message, GrouperOptions options)
        {
            if (message is TraceMessage)
            {
                Logger.Trace(message.GetMessage());
            }
            else if (message is DebugMessage)
            {
                Logger.Debug(message.GetMessage());
            }
            else if (message is InfoMessage)
            {
                Logger.Info(message.GetMessage());
            } // Handle file result messages from snafflin'.
            else if (message is FileResultMessage)
            {
                Logger.Warn(message.GetMessage());
            }
            else if (message is GpoResultMessage)
            {
                Logger.Warn(message.GetMessage());
            }
            else if (message is ErrorMessage)
            {
                Logger.Error(message.GetMessage());
            }
            else if (message is FatalMessage)
            {
                Logger.Fatal(message.GetMessage());
                if (Debugger.IsAttached)
                {
                    Console.WriteLine("Press any key to exit.");
                    Console.ReadKey();
                }
                return true;
            }
            else if (message is FinishMessage)
            {
                Logger.Info(message.GetMessage());
                if (Debugger.IsAttached)
                {
                    Console.WriteLine("Press any key to exit.");
                    Console.ReadKey();
                }
                return true;
            }
            return false;
        }
    }
}
