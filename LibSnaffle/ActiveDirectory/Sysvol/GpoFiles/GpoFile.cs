using LibSnaffle.Concurrency;
using System;
using System.Collections.Generic;
using System.IO;

namespace LibSnaffle.ActiveDirectory
{
    public abstract class GpoFile
    {
        public BlockingMq Logger;
        public string FilePath { get; set; }
        public List<GpoSetting> Settings { get; protected set; } = new List<GpoSetting>();
        public FileInfo Info { get; protected set; }

        protected GpoFile(string filepath, FileInfo info, BlockingMq logger)
        {
            FilePath = filepath;
            Info = info;
            Logger = logger;
        }

        protected string[] GetContentLines()
        {
            string[] lines = System.IO.File.ReadAllLines(FilePath);

            List<String> lineList = new List<string>();

            foreach (string line in lines)
            {
                if (line.StartsWith(";"))
                {
                    continue;
                }
                else
                {
                    lineList.Add(line);
                }
            }

            return lineList.ToArray();
        }

        protected string GetContentString()
        {
            string[] lines = GetContentLines();
            return String.Join(Environment.NewLine, lines);
        }

        protected string GetContentString(string[] lines)
        {
            return String.Join(Environment.NewLine, lines);
        }

        public abstract void Parse();
    }
}
