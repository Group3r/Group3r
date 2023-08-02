using LibSnaffle.Classifiers.Results;
using LibSnaffle.Classifiers.Rules;
using LibSnaffle.Concurrency;
using System;
using System.IO;

namespace LibSnaffle.Classifiers
{
    public static class SysvolSwitch
    {
        public static bool ScanSysvol { get; set; } = true;
        public static bool ScanNetlogon { get; set; } = true;
    }
    public class ShareClassifier : ClassifierBase
    {

        public ShareClassifier(BlockingMq mq, ClassifierOptions options) : base(options, mq)
        {
        }

        public override Result Classify(ClassifierRule classifierRule, string share)
        {
            // first time we hit sysvol, toggle the flag and keep going. every other time, bail out.
            if (share.ToLower().EndsWith("sysvol"))
            {
                if (SysvolSwitch.ScanSysvol == false)
                {
                    return null;
                }
                SysvolSwitch.ScanSysvol = false;
            };
            // same for netlogon
            if (share.ToLower().EndsWith("netlogon"))
            {
                if (SysvolSwitch.ScanNetlogon == false)
                {
                    return null;
                }
                SysvolSwitch.ScanNetlogon = false;
            }
            // check if it matches
            TextClassifier textClassifier = new TextClassifier(Mq, Options);
            TextResult textResult = (TextResult)textClassifier.Classify(classifierRule, share);
            if (textResult != null)
            {
                // if it does, see what we're gonna do with it
                switch (classifierRule.MatchAction)
                {
                    case Constants.MatchAction.Discard:
                        return null;
                    case Constants.MatchAction.Snaffle:
                        // in this context snaffle means 'send a report up the queue but don't scan the share'
                        if (IsShareReadable(share))
                        {
                            ShareResult shareResult = new ShareResult()
                            {
                                Triage = classifierRule.Triage,
                                Listable = true,
                                SharePath = share,
                                MatchedRule = classifierRule,
                            };
                            return shareResult;
                        }
                        else
                        {
                            return null;
                        }
                    default:
                        Mq.Error("You've got a misconfigured share ClassifierRule named " + classifierRule.RuleName + ".");
                        return null;
                }
            }
            return null;
        }

        internal bool IsShareReadable(string share)
        {
            try
            {
                string[] files = Directory.GetFiles(share);
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
            catch (Exception e)
            {
                Mq.Trace(e.ToString());
            }
            return false;
        }
    }
}