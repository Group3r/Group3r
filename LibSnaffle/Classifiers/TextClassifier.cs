using LibSnaffle.Classifiers.Results;
using LibSnaffle.Concurrency;
using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace LibSnaffle.Classifiers
{
    public class TextClassifier : ClassifierBase
    {
        public TextClassifier(BlockingMq mq, ClassifierOptions options) : base(options, mq)
        {
        }

        public override Result Classify(ClassifierRule classifierRule, string input)
        {
            foreach (Regex regex in classifierRule.Regexes)
            {
                try
                {
                    if (regex.IsMatch(input))
                    {
                        return new TextResult()
                        {
                            MatchedStrings = new List<string>() { regex.ToString() },
                            MatchContext = GetContext(input, regex),
                            MatchedRule = classifierRule
                        };
                    }
                }
                catch (Exception e)
                {
                    Mq.Error(e.ToString());
                }
            }

            return null;
        }

        private string GetContext(string original, Regex matchRegex)
        {
            try
            {
                if (Options.MatchContextBytes == 0)
                {
                    return "";
                }

                if ((original.Length < 6) || (original.Length < Options.MatchContextBytes * 2))
                {
                    return original;
                }

                int foundIndex = matchRegex.Match(original).Index;

                int contextStart = SubtractWithFloor(foundIndex, Options.MatchContextBytes, 0);
                string matchContext = "";

                if (original.Length <= (contextStart + (Options.MatchContextBytes * 2)))
                {
                    return Regex.Escape(original.Substring(contextStart));
                }

                if (Options.MatchContextBytes > 0) matchContext = original.Substring(contextStart, Options.MatchContextBytes * 2);

                return Regex.Escape(matchContext);
            }
            catch (Exception e)
            {
                Mq.Error(e.ToString());
            }

            return "";
        }

        internal int SubtractWithFloor(int num1, int num2, int floor)
        {
            int result = num1 - num2;
            if (result <= floor) return floor;
            return result;
        }
    }
}