using LibSnaffle.Classifiers.Results;
using LibSnaffle.Classifiers.Rules;
using LibSnaffle.Concurrency;
using System.IO;

namespace LibSnaffle.Classifiers
{
    public class DirClassifier : ClassifierBase
    {
        public DirClassifier(BlockingMq mq, ClassifierOptions options) : base(options, mq)
        {
        }

        public override Result Classify(ClassifierRule classifierRule, string dir)
        {
            DirectoryInfo dirInfo = new System.IO.DirectoryInfo(dir);

            DirResult dirResult = new DirResult(dirInfo);

            // check if it matches
            TextClassifier textClassifier = new TextClassifier(Mq, Options);
            TextResult textResult = (TextResult)textClassifier.Classify(classifierRule, dir);
            if (textResult != null)
            {
                // if it does, see what we're gonna do with it
                switch (classifierRule.MatchAction)
                {
                    case Constants.MatchAction.Discard:
                        dirResult.ScanDir = false;
                        return dirResult;
                    case Constants.MatchAction.Snaffle:
                        dirResult.ScanDir = false;
                        dirResult.Triage = classifierRule.Triage;
                        return dirResult;
                    default:
                        Mq.Error("You've got a misconfigured file ClassifierRule named " + classifierRule.RuleName + ".");
                        return null;
                }
            }
            return dirResult;
        }
    } 
}
