using System;

namespace LibSnaffle.Errors
{
    /// <summary>
    /// Represents an Exception to be used when an issue arises trying to parse a domain user.
    /// </summary>
    public class UserException : Exception
    {
        public UserException(string msg) : base(msg) { }
        public UserException(string msg, Exception inner) : base(msg, inner) { }
    }
}
