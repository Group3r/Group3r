namespace LibSnaffle.Concurrency
{
    public class FatalMessage : QueueMessage
    {
        public override string GetMessage()
        {
            string datetime = MsgDateTime.ToString($"yyyy-MM-dd{Delimeter}HH:mm:ss{Delimeter}zzz{Delimeter}");
            return $"{datetime}[Fatal]{Delimeter}{MessageString}";
        }
    }
}
