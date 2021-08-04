using CommandLineParser.Arguments;
using Group3r.Concurrency;
using Nett;
using NLog;
using System;
using System.Linq;
using CommandLineParser.Exceptions;

namespace Group3r.Options
{
    /**
     * Summary: Static class to house cmd argument parsing into options.
     * TODO: Max thread settings are currently hardcoded and cmd args are no respected.
     */
    public static class OptionsParser
    {
        /**
         * Summary: Defines cmd line args and adds them to a parser.
         * Arguments: None
         * Returns: CommandLineParser.CommandLineParser object
         */
        private static CommandLineParser.CommandLineParser BuildParser()
        {
            CommandLineParser.CommandLineParser parser = new CommandLineParser.CommandLineParser();

            // letters i haven't used abegijklmnw
            parser.Arguments.Add(new ValueArgument<string>('z', "config", "Path to a .toml config file. Run with \'generate\' to puke a sample config file into the working directory."));
            parser.Arguments.Add(new ValueArgument<string>('c', "dc", "Target Domain controller"));
            parser.Arguments.Add(new ValueArgument<string>('d', "domain", "Domain to query."));
            parser.Arguments.Add(new SwitchArgument('h', "help", "Displays this help.", false));
            parser.Arguments.Add(new SwitchArgument('o', "offline", "Disables checks that require LDAP comms with a DC or SMB comms with file shares found in policy settings. Requires that you define a value for -s.", false));
            parser.Arguments.Add(new ValueArgument<string>('f', "outfile", "Path for output file. You probably want this if you're not using -s."));
            parser.Arguments.Add(new ValueArgument<string>('p', "password", "Password to use for LDAP operations."));
            parser.Arguments.Add(new SwitchArgument('q', "quiet", "Enables quiet mode. Turns off progress updates.", false));
            parser.Arguments.Add(new SwitchArgument('s', "stdout", "Enables outputting results to stdout as soon as they're found. You probably want this if you're not using -o.", false));
            parser.Arguments.Add(new ValueArgument<string>('y', "sysvol", "Set the path to a domain SYSVOL directory."));
            parser.Arguments.Add(new ValueArgument<int>('t', "threads", "Max number of threads. Defaults to 10."));
            parser.Arguments.Add(new ValueArgument<string>('u', "username", "Username to use for LDAP operations."));
            parser.Arguments.Add(new ValueArgument<string>('v', "verobsity", "Sets verobsity level. Do you want degubs?"));
            parser.Arguments.Add(new SwitchArgument('r', "currentonly", "Only checks current policies, ignoring stuff in those Policies_NTFRS_* directories that result from replication failures.", false));
            parser.Arguments.Add(new ValueArgument<string>('x', "printer", "Type of output to display. Options are none, minimal, or json."));
            parser.Arguments.Add(new SwitchArgument('w', "findingsonly", "Only displays settings that had an associated finding.", false));
            return parser;
        }

        /**
         * Summary: Parses the actual cmd line args provided into an Options object.
         *          Also submits some messages to the Mq regarding config.
         * Arguments: Array of command line args
         * Returns: GroupCoreOptions object
         */
        public static GrouperOptions Parse(string[] args, GrouperMq mq)
        {
            GrouperOptions options = new GrouperOptions();
            CommandLineParser.CommandLineParser parser = BuildParser();

            // extra check to handle builtin behaviour from cmd line arg parser
            if ((args.Contains("--help") || args.Contains("/?") || args.Contains("help") || args.Contains("-h") || args.Length == 0))
            {
                parser.ShowUsage();
                // TODO: avoid an exit like this, prefer to return to caller.
                Environment.Exit(0);
            }

            TomlSettings settings = TomlSettings.Create(cfg => cfg
                .ConfigureType<LogLevel>(tc => tc
                    .WithConversionFor<TomlString>(conv => conv
                        .FromToml(s => (LogLevel)Enum.Parse(typeof(LogLevel), s.Value, ignoreCase: true))
                        .ToToml(e => e.ToString()))));

            parser.ParseCommandLine(args);

            // Iterate over each arg where parsed is True.
            foreach (Argument arg in parser.Arguments.FindAll(a => a.Parsed))
            {
                // Grab the value here to save typecasting every instance of ValueArgument.
                string value = "";
                if (arg is ValueArgument<string>)
                {
                    value = ((ValueArgument<string>)arg).Value;
                }
                else if(arg is ValueArgument<int>)
                {
                    value = ((ValueArgument<int>)arg).Value.ToString();
                }

                switch (arg.LongName)
                {
                    case "config":
                        if (value.Equals("generate"))
                        {
                            // Generate a default config and return.
                            Toml.WriteFile(options, ".\\default.toml", settings);
                            mq.Info("Wrote default config values to .\\default.toml");
                            mq.Terminate();
                        }
                        else
                        {
                            // Read the specified config file and return.
                            options = Toml.ReadFile<GrouperOptions>(value, settings);
                            mq.Info("Read config file from " + value);
                        }
                        return options;
                    case "offline":
                        options.OfflineMode = true;
                        break;
                    case "outfile":
                        if (!String.IsNullOrEmpty(value))
                        {
                            options.LogToFile = true;
                            options.LogFilePath = value;
                            mq.Degub("Logging to file at " + options.LogFilePath);
                        }
                        break;
                    case "verobsity":
                        options.LogLevelString = value;
                        mq.Degub("Requested verbosity level: " + options.LogLevelString);
                        break;
                    case "stdout":
                        // If enabled, display findings to the console.
                        options.LogToConsole = true;
                        mq.Degub("Enabled logging to stdout.");
                        break;
                    case "domain":
                        // Args that tell us about targeting.
                        if (!String.IsNullOrEmpty(value))
                        {
                            options.TargetDomain = value;
                            mq.Degub("Target domain is " + value);
                        }
                        break;
                    case "username":
                        if (!String.IsNullOrEmpty(value))
                        {
                            options.Username = value;
                            mq.Degub("Username for LDAP is " + value);
                        }
                        break;
                    case "password":
                        if (!String.IsNullOrEmpty(value))
                        {
                            options.Password = value;
                            mq.Degub("Password for LDAP is " + value);
                        }
                        break;
                    case "quiet":
                        options.QuietMode = true;
                        break;
                    case "dc":
                        options.TargetDc = value;
                        mq.Degub("Target DC is " + value);
                        break;
                    case "sysvol":
                        options.SysvolPath = value;
                        mq.Degub("Disabled finding SYSVOL automatically.");
                        mq.Degub("Target SYSVOL path is " + value);
                        break;
                    case "currentonly":
                        options.CurrentPolOnly = true;
                        break;
                    case "findingsonly":
                        options.FindingsOnly = true;
                        break;
                    case "threads":
                        options.MaxThreads = int.Parse(value);
                        break;
                    case "printer":
                        options.PrinterType = value;
                        break;
                    default:
                        throw new CommandLineArgumentException("Something went real squirrelly in the command line args.", value);
                }
            }

            // Quality bants with dumbo users
            if (!options.LogToConsole && !options.LogToFile)
            {
                throw new ArgumentException("You didn't enable output to file or to the console so you won't see any results or debugs or anything. Your l0ss.");
            }
            if (string.IsNullOrEmpty(options.SysvolPath) && options.OfflineMode)
            {
                throw new ArgumentException("You have specified offline mode but not specified a path to SysVol. I can just make shit up I guess?");
            }

            mq.Info("Parsed args successfully.");
            return options;
        }
    }
}