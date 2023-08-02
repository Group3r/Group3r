using BigFish.Options;
using LibSnaffle.Concurrency;

namespace BigFish.View
{
    /**
     * Summary: Defines the interface for msg processing behaviour.
     */
    interface IMessageProcessor
    {
        bool ProcessMessage(QueueMessage message, GrouperOptions options);
    }
}
