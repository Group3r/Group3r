using LibSnaffle.Classifiers.Results;
using LibSnaffle.Concurrency;

namespace Group3r
{
    public class FileResultMessage : QueueMessage
    {
        public override string GetMessage()
        {
            string datetime = MsgDateTime.ToString($"yyyy-MM-dd{Delimeter}HH:mm:ss{Delimeter}zzz{Delimeter}");

            string context = Result.TextResult != null ? Result.TextResult.MatchContext : "";
            string matchedString = Result.TextResult != null ? Result.TextResult.MatchedStrings[0] : "";
            string msg = $"{{{Result.MatchedRule.Triage}}}<{Result.MatchedRule.RuleName}|{(Result.RwStatus.CanRead ? "R" : "")}{(Result.RwStatus.CanWrite ? "W" : "")}{(Result.RwStatus.CanModify ? "M" : "")}|{matchedString}|Lengthoffile>({Result.ResultFileInfo.FullName}){context}";
            return $"{datetime}[HOSTSTRING] [File]{Delimeter}{msg}";
        }
        public FileResult Result { get; set; }
    }
}