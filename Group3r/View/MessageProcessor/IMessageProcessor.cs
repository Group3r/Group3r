using Group3r.Options;
using LibSnaffle.Concurrency;

namespace Group3r.View
{
    /**
     * Summary: Defines the interface for msg processing behaviour.
     */
    interface IMessageProcessor
    {
        bool ProcessMessage(QueueMessage message, GrouperOptions options);
    }
}
