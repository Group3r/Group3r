using Group3r.Assessment;
using LibSnaffle.Concurrency;

namespace Group3r
{
    public class GpoResultMessage : QueueMessage
    {
        public GpoResult GpoResult { get; set; }

        public override string GetMessage()
        {
            string datetime = MsgDateTime.ToString($"yyyy-MM-dd{Delimeter}HH:mm:ss{Delimeter}zzz{Delimeter}");
            return $"{datetime}[GPO]{Delimeter}{MessageString}";
        }
    }
}
