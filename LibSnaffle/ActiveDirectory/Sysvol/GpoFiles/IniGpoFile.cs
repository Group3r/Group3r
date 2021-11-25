using LibSnaffle.Concurrency;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace LibSnaffle.ActiveDirectory
{
    class IniGpoFile : GpoFile
    {
        public IniGpoFile(string filepath, FileInfo info, BlockingMq logger) : base(filepath, info, logger)
        {
        }

        public override void Parse()
        {
            GetSettings();
        }

        public void GetSettings()
        {
            //define what a heading looks like
            Regex headingRegex = new Regex(@"^\[(\w+\s?)+\]$");

            string[] infContentArray = File.ReadAllLines(FilePath);

            string infContentString = string.Join(Environment.NewLine, infContentArray);

            if (String.IsNullOrWhiteSpace(infContentString))
            {
                return;
            }

            List<int> headingLines = new List<int>();
            //find all the lines that look like a heading and put the line numbers in an array.
            int i = 0;
            foreach (string infLine in infContentArray)
            {
                Match headingMatch = headingRegex.Match(infLine);
                if (headingMatch.Success)
                {
                    headingLines.Add(i);
                }
                i++;
            }
            // make a dictionary with K/V = start/end of each section
            // this is extraordinarily janky but it works mostly.
            Dictionary<int, int> sectionSlices = new Dictionary<int, int>();
            int fuck = 0;
            while (true)
            {
                try
                {
                    int sectionHeading = headingLines[fuck];
                    int sectionFinalLine = (headingLines[(fuck + 1)] - 1);
                    sectionSlices.Add(sectionHeading, sectionFinalLine);
                    fuck++;
                }
                catch (ArgumentOutOfRangeException)
                {
                    int sectionHeading = headingLines[fuck];
                    int sectionFinalLine = infContentArray.Length - 1;
                    sectionSlices.Add(sectionHeading, sectionFinalLine);
                    break;
                }
            }

            // iterate over the identified sections and get the heading and contents of each.
            foreach (KeyValuePair<int, int> sectionSlice in sectionSlices)
            {
                //get the section heading
                char[] squareBrackets = { '[', ']' };
                string sectionSliceKey = infContentArray[sectionSlice.Key];
                string sectionHeading = sectionSliceKey.Trim(squareBrackets);
                //get the line where the section content starts by adding one to the heading's line
                int firstLineOfSection = (sectionSlice.Key + 1);
                //get the first line of the next section
                int lastLineOfSection = sectionSlice.Value;
                //subtract one from the other to get the section length, without the heading.
                int sectionLength = (lastLineOfSection - firstLineOfSection + 1);
                //get an array segment with the lines
                ArraySegment<string> sectionContent =
                    new ArraySegment<string>(infContentArray, firstLineOfSection, sectionLength);

                // BE DEV DO CRIMES
                Dictionary<int, List<string>> linesDict = new Dictionary<int, List<string>>();

                //iterate over the lines in the section;
                for (int b = sectionContent.Offset; b < (sectionContent.Offset + sectionContent.Count); b++)
                {
                    // get the actual fucking line
                    string line = sectionContent.Array[b];
                    // get the subsection index number off the front of the line
                    string lineIndexString = line.Substring(0, 1);
                    int lineIndex;

                    if (int.TryParse(lineIndexString, out lineIndex))
                    {
                        if (linesDict.Keys.Contains(lineIndex))
                        {
                            linesDict[lineIndex].Add(line.Substring(1));
                        }
                        else
                        {
                            linesDict.Add(lineIndex, new List<string>() { line.Substring(1) });
                        }
                    }
                    else if (lineIndexString == "E" | lineIndexString == "S")
                    {
                        Logger.Trace("Ignore StartExecutePSFirst or EndExecutePSFirst configuration");
                    }
                    else
                    {
                        if (Logger != null)
                        {
                            Logger.Error("Something went wrong with the scripts.ini parsing and the int casting and the GLAYVIN!");
                        }
                    }
                }

                foreach (KeyValuePair<int, List<string>> subsection in linesDict)
                {
                    ScriptSetting scriptSetting = new ScriptSetting();

                    switch (sectionHeading)
                    {
                        case "Startup":
                            scriptSetting.ScriptType = ScriptType.Startup;
                            break;
                        case "Shutdown":
                            scriptSetting.ScriptType = ScriptType.Shutdown;
                            break;
                        case "Logon":
                            scriptSetting.ScriptType = ScriptType.Logon;
                            break;
                        case "Logoff":
                            scriptSetting.ScriptType = ScriptType.Logoff;
                            break;
                        default:
                            if (Logger != null)
                            {
                                Logger.Error("There is a type of Scripts.Ini entry that I'm not handling properly. Fuck. " + sectionHeading);
                            }
                            break;
                    }

                    foreach (string line in subsection.Value)
                    {
                        string[] splitLine = line.Split('=');
                        if (splitLine[0] == "CmdLine")
                        {
                            scriptSetting.CmdLine = splitLine[1];
                        }
                        else if (splitLine[0] == "Parameters")
                        {
                            scriptSetting.Parameters = splitLine[1];
                        }
                        else
                        {
                            if (Logger != null)
                            {
                                Logger.Error("I dunno what the hell a " + splitLine[0] + " is but it scares me.");
                            }
                        }
                    }
                    scriptSetting.Source = FilePath;
                    Settings.Add(scriptSetting);
                }
            }
        }
    }
}
