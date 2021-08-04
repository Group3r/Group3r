using LibSnaffle.Concurrency;

namespace LibSnaffle.FileDiscovery
{
    /// <summary>
    /// Class to store a queue and a file path.
    /// </summary>
    /// <remarks>
    /// Used to encapsulate a queue and file path for processing by an Action delegate through TaskFactory.StartNew().
    /// </remarks>
    public class QueueAndPath
    {
        public string Path { get; set; }
        public BlockingMq Mq;

        public QueueAndPath(BlockingMq q, string path)
        {
            Path = path;
            Mq = q;
        }
    }
}
