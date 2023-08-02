using LibSnaffle.Classifiers.Results;
using LibSnaffle.Concurrency;

namespace LibSnaffle.Classifiers
{
    /// <summary>
    /// Class to provide the mechanism to run rules against artefacts.
    /// </summary>
    public abstract class ClassifierBase
    {
        protected ClassifierRules AllRules { get; set; }
        protected ClassifierOptions Options { get; set; }
        protected BlockingMq Mq { get; set; }

        public ClassifierBase(ClassifierOptions options, BlockingMq mq)
        {
            Mq = mq;
            AllRules = options.AllRules;
            Options = options;
        }

        /// <summary>
        /// Provides the logic to apply a rule to the artefact.
        /// </summary>
        /// <param name="classifierRule">The rule to run</param>
        /// <param name="artefact">The string representing the artefact. E.g path to a file.</param>
        /// <returns></returns>
        public abstract Result Classify(ClassifierRule classifierRule, string artefact);
    }
}
