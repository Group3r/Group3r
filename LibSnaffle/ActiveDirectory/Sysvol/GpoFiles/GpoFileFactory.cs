using LibSnaffle.Concurrency;
using System;
using System.IO;

namespace LibSnaffle.ActiveDirectory
{
    public static class GpoFileFactory
    {
        public static GpoFile GetFile(string filePath, BlockingMq logger)
        {
            FileInfo info = new FileInfo(filePath);
            GpoFile newFile = null;

            if (string.Equals(info.Name.ToLower(), "gpttmpl.inf"))
            {
                newFile = new InfGpoFile(filePath, info, logger);
            }
            else if (string.Equals(info.Name.ToLower(), "scripts.ini"))
            {
                newFile = new IniGpoFile(filePath, info, logger);
            }
            else if (string.Equals(info.Name.ToLower(), "registry.pol"))
            {
                newFile = new PolGpoFile(filePath, info, logger);
            }
            else if (string.Equals(info.Extension.ToLower(), ".xml"))
            {
                newFile = new XmlGpoFile(filePath, info, logger);
            }
            else
            {
                throw new NotImplementedException("No parser for " + filePath);
            }

            return newFile;
        }
    }
}
