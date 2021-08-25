using LibSnaffle.Concurrency;
using System;
using System.IO;
using System.Linq;
using System.Text;

namespace LibSnaffle.ActiveDirectory
{
    /// <summary>
    /// Represents a .pol file found within a GPO directory.
    /// </summary>
    public class PolGpoFile : GpoFile
    {
        private const uint SIGNATURE = 0x67655250;
        private static Array ValueTypes = Enum.GetValues(typeof(RegKeyValType));
        public uint Signature { get; set; }
        public uint Version { get; set; }

        public PolGpoFile(string filepath, FileInfo info, BlockingMq logger) : base(filepath, info, logger)
        {
        }

        public override void Parse()
        {
            this.GetSettings();
        }

        public void GetSettings()
        {
            using (var file = File.OpenRead(FilePath))
            using (var reader = new BinaryReader(file, Encoding.Unicode))
            {
                this.Signature = reader.ReadUInt32();
                if (this.Signature != SIGNATURE)
                {
                    throw new NotSupportedException("File format is not supported");
                }
                this.Version = reader.ReadUInt32();

                var length = reader.BaseStream.Length;
                while (reader.BaseStream.Position < length)
                {
                    RegistrySetting setting = new RegistrySetting();
                    reader.ReadChar();
                    string keyPath = ReadString(reader);
                    string[] splitKeyPath = keyPath.Split('\\');
                    //  these don't say a hive, the hive is determined by whether it's user policy or machine policy, so it's always either hkcu or hklm.
                    if (this.FilePath.ToLower().Contains("\\machine\\"))
                    {
                        setting.Hive = RegHive.HKEY_LOCAL_MACHINE;
                    }
                    else if (this.FilePath.ToLower().Contains("\\user\\"))
                    {
                        setting.Hive = RegHive.HKEY_CURRENT_USER;
                    }
                    else
                    {
                        throw new NotImplementedException("Something went wrong trying to figure out the hive associated with this registry.pol file:" + FilePath);
                    }
                    setting.Key = String.Join("\\", splitKeyPath.Skip(1));
                    reader.ReadChar();
                    RegistryValue regVal = new RegistryValue();
                    regVal.ValueName = ReadString(reader);
                    reader.ReadChar();
                    regVal.RegKeyValType = (RegKeyValType)reader.ReadUInt32();
                    reader.ReadChar();
                    UInt32 settingSize = reader.ReadUInt32();
                    reader.ReadChar();
                    regVal.ValueBytes = reader.ReadBytes((int)settingSize);
                    regVal.ValueString = Encoding.Unicode.GetString(regVal.ValueBytes, 0, regVal.ValueBytes.Length);
                    reader.ReadChar();
                    setting.Values.Add(regVal);
                    Settings.Add(setting);
                }
            }
        }

        private static string ReadString(BinaryReader reader)
        {
            char current;
            string temp = string.Empty;
            while ((current = reader.ReadChar()) != '\0')
            {
                temp += current;
            }

            return temp;
        }

    }
}