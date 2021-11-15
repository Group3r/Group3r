using LibSnaffle.Classifiers.Results;
using LibSnaffle.Classifiers.Rules;
using LibSnaffle.Concurrency;
using System;
using System.IO;
using System.Security.Cryptography;

namespace LibSnaffle.Classifiers
{
    public class ContentClassifier : ClassifierBase
    {
        public ContentClassifier(BlockingMq mq, ClassifierOptions options) : base(options, mq)
        {

        }

        public override Result Classify(ClassifierRule classifierRule, string artefact)
        {
            FileInfo fileInfo = new FileInfo(artefact);
            FileResult fileResult;
            try
            {
                if (Options.MaxSizeToGrep >= fileInfo.Length)
                {
                    // figure out if we need to look at the content as bytes or as string.
                    switch (classifierRule.MatchLocation)
                    {
                        case Constants.MatchLoc.FileContentAsBytes:
                            byte[] fileBytes = File.ReadAllBytes(fileInfo.FullName);
                            if (ByteMatch(fileBytes))
                            {
                                fileResult = new FileResult(fileInfo, Options.CopyFile, Options.MaxSizeToCopy, Options.PathToCopyTo)
                                {
                                    MatchedRule = classifierRule
                                };
                                return fileResult;
                            }
                            else
                            {
                                return null;
                            }
                        case Constants.MatchLoc.FileContentAsString:
                            try
                            {
                                string fileString = File.ReadAllText(fileInfo.FullName);

                                TextClassifier textClassifier = new TextClassifier(Mq, Options);
                                TextResult textResult = (TextResult)textClassifier.Classify(classifierRule, fileString);

                                if (textResult != null)
                                {
                                    fileResult = new FileResult(fileInfo, Options.CopyFile, Options.MaxSizeToCopy, Options.PathToCopyTo)
                                    {
                                        MatchedRule = classifierRule,
                                        TextResult = textResult
                                    };
                                    return fileResult;
                                }
                            }
                            catch (UnauthorizedAccessException)
                            {
                                return null;
                            }
                            catch (IOException)
                            {
                                return null;
                            }
                            return null;
                        case Constants.MatchLoc.FileLength:
                            try
                            {
                                bool lengthResult = SizeMatch(fileInfo, classifierRule);
                                if (lengthResult)
                                {
                                    fileResult = new FileResult(fileInfo, Options.CopyFile, Options.MaxSizeToCopy, Options.PathToCopyTo)
                                    {
                                        MatchedRule = classifierRule
                                    };
                                    return fileResult;
                                }
                            }
                            catch (UnauthorizedAccessException)
                            {
                                return null;
                            }
                            catch (IOException)
                            {
                                return null;
                            }
                            return null;
                        case Constants.MatchLoc.FileMD5:
                            try
                            {
                                bool Md5Result = MD5Match(fileInfo, classifierRule);
                                if (Md5Result)
                                {
                                    fileResult = new FileResult(fileInfo, Options.CopyFile, Options.MaxSizeToCopy, Options.PathToCopyTo)
                                    {
                                        MatchedRule = classifierRule
                                    };
                                    return fileResult;
                                }
                            }
                            catch (UnauthorizedAccessException)
                            {
                                return null;
                            }
                            catch (IOException)
                            {
                                return null;
                            }
                            return null;
                        default:
                            Mq.Error("You've got a misconfigured file ClassifierRule named " + classifierRule.RuleName + ".");
                            return null;
                    }
                }
                else
                {
                    Mq.Trace("The following file was bigger than the MaxSizeToGrep config parameter:" + fileInfo.FullName);
                }
            }
            catch (Exception e)
            {
                Mq.Error(e.ToString());
                return null;
            }
            return null;
        }

        public bool SizeMatch(FileInfo fileInfo, ClassifierRule classifierRule)
        {
            if (classifierRule.MatchLength == fileInfo.Length)
            {
                return true;
            }
            return false;
        }

        public bool MD5Match(FileInfo fileInfo, ClassifierRule classifierRule)
        {
            string md5Sum = GetMD5HashFromFile(fileInfo.FullName);
            if (md5Sum == classifierRule.MatchMD5.ToUpper())
            {
                return true;
            }
            return false;
        }
        protected string GetMD5HashFromFile(string fileName)
        {
            using (var md5 = MD5.Create())
            {
                using (var stream = File.OpenRead(fileName))
                {
                    return BitConverter.ToString(md5.ComputeHash(stream)).Replace("-", string.Empty);
                }
            }
        }
        public bool ByteMatch(byte[] fileBytes)
        {
            // TODO
            throw new NotImplementedException(message: "Haven't implemented byte-based content searching yet lol.");
        }
    }
}