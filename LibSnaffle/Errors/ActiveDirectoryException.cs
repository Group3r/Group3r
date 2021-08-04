using System;

namespace LibSnaffle.Errors
{
    /// <summary>
    /// Represents an Exception to be used when an ActiveDirectory fails to be constructed.
    /// </summary>
    public class ActiveDirectoryException : Exception
    {
        public ActiveDirectoryException(string msg) : base(msg) { }
        public ActiveDirectoryException(string msg, Exception inner) : base(msg, inner) { }
    }
}
