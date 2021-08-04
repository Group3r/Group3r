using LibSnaffle.Classifiers.Results;
using LibSnaffle.Classifiers.Rules;
using LibSnaffle.Concurrency;
using System;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;

namespace LibSnaffle.Classifiers
{
    /// <summary>
    /// Classifier implementation to classify a file.
    /// </summary>
    public class FileClassifier : ClassifierBase
    {
        public FileClassifier(BlockingMq mq, ClassifierOptions options) : base(options, mq)
        {

        }

        public override Result Classify(ClassifierRule classifierRule, string artefact)
        {
            FileInfo fileToClassify = new FileInfo(artefact);
            // figure out what part we gonna look at
            string stringToMatch = null;

            switch (classifierRule.MatchLocation)
            {
                case Constants.MatchLoc.FileExtension:
                    stringToMatch = fileToClassify.Extension;
                    // special handling to treat files named like 'thing.kdbx.bak'
                    if (stringToMatch == ".bak")
                    {
                        // strip off .bak
                        string subName = fileToClassify.Name.Replace(".bak", "");
                        stringToMatch = Path.GetExtension(subName);
                        // if this results in no file extension, put it back.
                        if (stringToMatch == "")
                        {
                            stringToMatch = ".bak";
                        }
                    }
                    // this is insane that i have to do this but apparently files with no extension return
                    // this bullshit
                    if (stringToMatch == "")
                    {
                        return null;
                    }
                    break;
                case Constants.MatchLoc.FileName:
                    stringToMatch = fileToClassify.Name;
                    break;
                case Constants.MatchLoc.FilePath:
                    stringToMatch = fileToClassify.FullName;
                    break;
                case Constants.MatchLoc.FileLength:
                    if (classifierRule.MatchLength != fileToClassify.Length)
                    {
                        return null;
                    }
                    break;
                default:
                    Mq.Error("You've got a misconfigured file classifier rule named " + classifierRule.RuleName + ".");
                    return null;
            }

            TextResult textResult = null;

            if (!String.IsNullOrEmpty(stringToMatch))
            {
                TextClassifier textClassifier = new TextClassifier(Mq, Options);
                // check if it matches
                textResult = (TextResult)textClassifier.Classify(classifierRule, stringToMatch);
                if (textResult == null)
                {
                    // if it doesn't we just bail now.
                    return null;
                }
            }

            FileResult fileResult;
            // if it matches, see what we're gonna do with it
            switch (classifierRule.MatchAction)
            {
                case Constants.MatchAction.Discard:
                    // chuck it.
                    return null;
                case Constants.MatchAction.Snaffle:
                    // snaffle that bad boy
                    fileResult = new FileResult(fileToClassify, Options.CopyFile, Options.MaxSizeToCopy, Options.PathToCopyTo)
                    {
                        MatchedRule = classifierRule,
                        MatchedString = stringToMatch,
                        TextResult = textResult
                    };
                    return fileResult;
                case Constants.MatchAction.CheckForKeys:
                    // do a special x509 dance
                    if (x509PrivKeyMatch(fileToClassify))
                    {
                        fileResult = new FileResult(fileToClassify, Options.CopyFile, Options.MaxSizeToCopy, Options.PathToCopyTo)
                        {
                            MatchedRule = classifierRule,
                            MatchedString = stringToMatch
                        };
                        return fileResult;
                    }
                    else
                    {
                        return null;
                    }
                case Constants.MatchAction.Relay:
                    // bounce it on to the next ClassifierRule
                    // TODO concurrency uplift make this a new task on the poolq
                    try
                    {
                        //TODO this needs to iterate over all relay rules
                        ClassifierRule nextRule = AllRules.AllClassifierRules.Where(x => x.RuleName.Equals(classifierRule.RelayTarget)).FirstOrDefault();
                        if(nextRule.EnumerationScope == Constants.EnumerationScope.ContentsEnumeration)
                        {
                            ContentClassifier c = new ContentClassifier(Mq, Options);
                            return c.Classify(nextRule, artefact);
                        }
                        throw new ArgumentException($"Incorrect Classifier Enumeration Scope on rule '{nextRule.RuleName}'");
                    }
                    catch (IOException e)
                    {
                        Mq.Trace(e.ToString());
                    }
                    catch (Exception e)
                    {
                        Mq.Error("You've got a misconfigured file ClassifierRule named " + classifierRule.RuleName + ".");
                        Mq.Trace(e.ToString());
                    }
                    return null;
                case Constants.MatchAction.EnterArchive:
                    // do a special looking inside archive files dance using
                    // https://github.com/adamhathcock/sharpcompress
                    // TODO FUUUUUCK
                    throw new NotImplementedException("Haven't implemented walking dir structures inside archives. Prob needs pool queue.");
                default:
                    Mq.Error("You've got a misconfigured file ClassifierRule named " + classifierRule.RuleName + ".");
                    return null;
            }
        }
       
        public bool x509PrivKeyMatch(FileInfo fileInfo)
        {
            try
            {
                X509Certificate2 parsedCert = new X509Certificate2(fileInfo.FullName);
                return parsedCert.HasPrivateKey;
            }
            catch (CryptographicException)
            {}
            return false;
        }
    }
}