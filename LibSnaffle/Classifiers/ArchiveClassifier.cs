using LibSnaffle.Classifiers.Results;
using LibSnaffle.Concurrency;
using System;


namespace LibSnaffle.Classifiers
{
    public class ArchiveClassifier : ClassifierBase
    {
        // TODO VERY WORK IN PROGRESS
        public ArchiveClassifier(BlockingMq mq, ClassifierOptions options) : base(options, mq)
        {

        }
        public override Result Classify(ClassifierRule rule, string file)
        {
            // look inside archives for files we like.
            /*
            FileInfo fileInfo = new FileInfo(file);
            try
            {
                IArchive archive = ArchiveFactory.Open(fileInfo.FullName);
                foreach (IArchiveEntry entry in archive.Entries)
                {
                    if (!entry.IsDirectory)
                    {
                        try
                        {
                            FileScanner.ScanFile(entry.Key);
                        }
                        catch (Exception e)
                        {
                            Mq.Trace(e.ToString());
                        }
                    }
                }
            }
            catch (CryptographicException)
            {
                FileResult result = new FileResult(fileInfo, CopyFile, MaxSizeToCopy, PathToCopyto)
                {
                    MatchedRule = new ClassifierRule() { Triage = Triage.Black, RuleName = "EncryptedArchive" }
                });
                return result;
            }
            catch (Exception e)
            {
                Mq.Trace(e.ToString());
            }
            return null;
            */
            throw new NotImplementedException();
        }
    }
}