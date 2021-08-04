using NLog;
using NLog.Config;
using NLog.Targets;
using System;
using System.Diagnostics;
using System.Text;
using System.Threading.Tasks;
using LibSnaffle.Concurrency;
using System.Collections.Generic;

namespace LibSnaffle.Logging
{
    /// <summary>
    /// Static methods for setting up the Nlog instance.
    /// </summary>
    /// <remarks>
    /// TODO: Could be improved to remove hardcoded values.
    /// </remarks>
    public class Logging
    {
        /// <summary>
        /// Custom log console.
        /// </summary>
        /// <param name="logToFile"></param>
        /// <param name="Mq"></param>
        /// <param name="logLevelString"></param>
        /// <param name="logFilePath"></param>
        /// <param name="logconsole"></param>
        public static void SetupLogger(bool logToFile, bool logToConsole, BlockingMq Mq, string logLevelString, string logFilePath, ColoredConsoleTarget logconsole)
        {
            LoggingConfiguration nlogConfig = new LoggingConfiguration();
            LogLevel logLevel = ParseLogLevelString(logLevelString, Mq);
            
            //bool logToConsole = !logToFile;

            // Targets where to log to: File and Console
            if (logToConsole)
            {
                
                nlogConfig.AddRule(logLevel, LogLevel.Fatal, logconsole);
                logconsole.Layout = "${message}";
            }

            if (logToFile)
            {
                FileTarget logfile = new FileTarget("logfile") { FileName = logFilePath };
                nlogConfig.AddRule(logLevel, LogLevel.Fatal, logfile);
                logfile.Layout = "${message}";
            }

            LogManager.Configuration = nlogConfig;
        }

        /// <summary>
        /// Default Log console.
        /// </summary>
        /// <param name="logToFile"></param>
        /// <param name="Mq"></param>
        /// <param name="logLevelString"></param>
        /// <param name="logFilePath"></param>
        public static void SetupLogger(bool logToFile, bool logToConsole, BlockingMq Mq, string logLevelString, string logFilePath)
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
                        new ConsoleWordHighlightingRule("{Red}", ConsoleOutputColor.Red, ConsoleOutputColor.Black),
                        new ConsoleWordHighlightingRule("{Black}", ConsoleOutputColor.DarkGray, ConsoleOutputColor.Black),
                        new ConsoleWordHighlightingRule
                        {
                            CompileRegex = true,
                            Regex = @"^\d\d\d\d-\d\d\-\d\d \d\d:\d\d:\d\d [\+-]\d\d:\d\d ",
                            ForegroundColor = ConsoleOutputColor.DarkGray,
                            BackgroundColor = ConsoleOutputColor.Black
                        }
                    }
            };
            SetupLogger(logToFile, logToConsole, Mq, logLevelString, logFilePath, logconsole);
        }

        /**
         * Summary: Parses the loglevelstring option into a LogLevel.
         * Arguments: string logLevelString config optoin and the Mq.
         * Returns: LogLevel
         */
        private static LogLevel ParseLogLevelString(string logLevelString, BlockingMq Mq)
        {
            LogLevel logLevel;
            switch (logLevelString.ToLower())
            {
                case "debug":
                    logLevel = LogLevel.Debug;
                    Mq.Degub("Set verbosity level to degub.");
                    break;
                case "degub":
                    logLevel = LogLevel.Debug;
                    Mq.Degub("Set verbosity level to degub.");
                    break;
                case "trace":
                    logLevel = LogLevel.Trace;
                    Mq.Degub("Set verbosity level to trace.");
                    break;
                case "data":
                    logLevel = LogLevel.Warn;
                    Mq.Degub("Set verbosity level to data.");
                    break;
                case "info":
                    logLevel = LogLevel.Info;
                    Mq.Degub("Set verbosity level to info.");
                    break;
                default:
                    logLevel = LogLevel.Info;
                    Mq.Error("Invalid verbosity level " + logLevelString +
                             " falling back to default level (info).");
                    break;
            }
            return logLevel;
        }
    }
}
