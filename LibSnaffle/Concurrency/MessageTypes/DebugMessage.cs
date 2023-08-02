namespace LibSnaffle.Concurrency
{
    public class DebugMessage : QueueMessage
    {
        public override string GetMessage()
        {
            string datetime = MsgDateTime.ToString($"yyyy-MM-dd{Delimeter}HH:mm:ss{Delimeter}zzz{Delimeter}");
            return $"{datetime}[Degub]{Delimeter}{MessageString}";
        }
    }
}
