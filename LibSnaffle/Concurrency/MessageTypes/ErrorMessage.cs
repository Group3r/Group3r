namespace LibSnaffle.Concurrency
{
    public class ErrorMessage : QueueMessage
    {
        public override string GetMessage()
        {
            string datetime = MsgDateTime.ToString($"yyyy-MM-dd{Delimeter}HH:mm:ss{Delimeter}zzz");
            return $"{datetime}{Delimeter}[Error]{Delimeter}{MessageString}";
        }
    }
}
