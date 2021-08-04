using LibSnaffle.Classifiers.Results;
using System;
using System.Collections.Concurrent;

namespace LibSnaffle.Concurrency
{
    ///<summary>
    ///Class to provide an API for the BlockingCollection queue.
    ///This class should be used for queuing output to be printed or written to file.
    ///</summary>
    ///<remarks>
    ///This class stores the BlockingCollection that is the queue, and methods for adding different QueueMessages.
    ///This class can be extended to enqueue custom QueueMessage subclasses.
    ///</remarks>
    public class BlockingMq
    {
        /// <summary>
        /// The queue of QueueMessages
        /// </summary>
        public BlockingCollection<QueueMessage> Q { get; private set; }

        /// <summary>
        /// Default constructor.
        /// </summary>
        public BlockingMq()
        {
            Q = new BlockingCollection<QueueMessage>();
        }

        /// <summary>
        /// Checks if the queue is empty.
        /// </summary>
        /// <returns>
        /// Returns true if the queue is empty
        /// </returns>
        public bool IsEmpty()
        {
            return Q.Count == 0;
        }

        /// <summary>
        /// Removes a message from the queue and returns is.
        /// </summary>
        /// <returns>
        /// The popped QueueMessage instance.
        /// </returns>
        public QueueMessage Pop()
        {
            return Q.Take();
        }

        /// <summary>
        /// Enqueues a FatalMessage with a termination message.
        /// </summary>
        public void Terminate()
        {
            Q.Add(new FatalMessage
            {
                MsgDateTime = DateTime.Now,
                MessageString = "Terminate was called"
            });
        }

        /// <summary>
        /// Enqueues a TraceMessage.
        /// </summary>
        /// <param name="message">
        /// Message contents.
        /// </param>
        public void Trace(string message)
        {
            Q.Add(new TraceMessage
            {
                MsgDateTime = DateTime.Now,
                MessageString = message
            });
        }

        /// <summary>
        /// Enqueues a DebugMessage.
        /// </summary>
        /// <param name="message">
        /// Message contents.
        /// </param>
        public void Degub(string message)
        {
            Q.Add(new TraceMessage
            {
                MsgDateTime = DateTime.Now,
                MessageString = message
            });
        }

        /// <summary>
        /// Enqueues a InfoMessage.
        /// </summary>
        /// <param name="message">
        /// Message contents.
        /// </param>
        public void Info(string message)
        {
            Q.Add(new InfoMessage
            {
                MsgDateTime = DateTime.Now,
                MessageString = message
            });
        }

        /// <summary>
        /// Enqueues a ErrorMessage.
        /// </summary>
        /// <param name="message">
        /// Message contents.
        /// </param>
        public void Error(string message)
        {
            Q.Add(new ErrorMessage
            {
                MsgDateTime = DateTime.Now,
                MessageString = message
            });
        }

        /// <summary>
        /// Enqueues a FinishMessage with no content.
        /// </summary>
        public void Finish()
        {
            Q.Add(new FinishMessage()
            {
                MsgDateTime = DateTime.Now,
            });
        }
    }
}

