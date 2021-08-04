using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using LibSnaffle.Concurrency;

namespace LibSnaffle.ActiveDirectory
{
    public enum ScriptType
    {
        Logon,
        Logoff,
        Startup,
        Shutdown
    }
    public enum SettingAction
    {
        Update,
        Create,
        Remove,
        Add,
        Unknown
    }

    public enum PolicyType
    {
        Computer,
        User,
        Package
    }
    public class GpoSetting
    {
        public string Source { get; set; }
        public PolicyType PolicyType { get; set; }

        public SettingAction ParseSettingAction(string actionString)
        {
            switch (actionString)
            {
                case "C":
                    return SettingAction.Create;
                case "U":
                    return SettingAction.Update;
                case "R":
                    return SettingAction.Remove;
                case "ADD":
                    return SettingAction.Add;
                default:
                    return SettingAction.Unknown;
            }
        }

        public string DecryptCpassword(string cpassword)
        {
            if (cpassword == null)
            {
                return null;
            }

            // reimplemented based on @obscuresec's Get-GPPPassword PowerShell
            int cpassMod = cpassword.Length % 4;
            string padding = "";
            switch (cpassMod)
            {
                case 1:
                    padding = "=";
                    break;
                case 2:
                    padding = "==";
                    break;
                case 3:
                    padding = "=";
                    break;
            }
            string cpasswordPadded = cpassword + padding;
            byte[] decodedCpassword = Convert.FromBase64String(cpasswordPadded);
            AesCryptoServiceProvider aesProvider = new AesCryptoServiceProvider();
            byte[] aesKey = {0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9, 0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
                0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90, 0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b };
            aesProvider.IV = new byte[aesProvider.IV.Length];
            aesProvider.Key = aesKey;
            ICryptoTransform decryptor = aesProvider.CreateDecryptor();
            byte[] decryptedBytes = decryptor.TransformFinalBlock(decodedCpassword, 0, decodedCpassword.Length);
            string decryptedCpassword = Encoding.Unicode.GetString(decryptedBytes);
            return decryptedCpassword;
        }
    }
}
