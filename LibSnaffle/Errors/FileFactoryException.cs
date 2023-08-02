using System;

namespace LibSnaffle.Errors
{
    /// <summary>
    /// Represents an Exception to be used when an FileFactory fails to create a File.
    /// </summary>
    class FileFactoryException : Exception
    {
        public FileFactoryException(string msg) : base(msg) { }
        public FileFactoryException(string msg, Exception inner) : base(msg, inner) { }
    }
}

