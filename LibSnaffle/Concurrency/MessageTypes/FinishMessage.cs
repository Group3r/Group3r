namespace LibSnaffle.Concurrency
{
    public class FinishMessage : QueueMessage
    {
        public override string GetMessage()
        {
            string datetime = MsgDateTime.ToString($"yyyy-MM-dd{Delimeter}HH:mm:ss{Delimeter}zzz{Delimeter}");
            return $"{datetime}[Finish]{Delimeter}{MessageString}";
        }
    }
}
