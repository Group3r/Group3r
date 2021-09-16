namespace LibSnaffle.Concurrency
{
    public class TraceMessage : QueueMessage
    {
        public override string GetMessage()
        {
            string datetime = MsgDateTime.ToString($"yyyy-MM-dd{Delimeter}HH:mm:ss{Delimeter}zzz{Delimeter}");
            return $"{datetime}[Trace]{Delimeter}{MessageString}";
        }
    }
}
