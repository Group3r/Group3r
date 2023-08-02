using System;

namespace LibSnaffle.Concurrency
{
    /// <summary>
    /// Abstract class to represent a message to be queued in the BlockingMq.
    /// </summary>
    public abstract class QueueMessage
    {
        /// <summary>
        /// DateTime representing the time that the message was created.
        /// </summary>
        public DateTime MsgDateTime { get; set; }

        /// <summary>
        /// The content of the message.
        /// </summary>
        public string MessageString { protected get; set; }

        /// <summary>
        /// Represents the delimiter used to seperate message components when the output is constructed.
        /// Defaults to a single space.
        /// </summary>
        public string Delimeter { get; set; } = " ";

        /// <summary>
        /// Method to construct the messgage to be outputted.
        /// </summary>
        /// <returns>
        /// string containing the message ready for output.
        /// </returns>
        public abstract string GetMessage();

    }
}