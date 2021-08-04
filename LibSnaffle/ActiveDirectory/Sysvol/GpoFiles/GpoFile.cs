using LibSnaffle.ActiveDirectory;
using LibSnaffle.Concurrency;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
            return System.IO.File.ReadAllLines(FilePath);
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
