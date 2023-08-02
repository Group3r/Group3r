using System;

namespace LibSnaffle.Errors
{
    /// <summary>
    /// Represents an Exception to be used when a GPO fails to be constructed.
    /// </summary>
    public class GpoException : Exception
    {

        public GpoException(string msg) : base(msg) { }
        public GpoException(string msg, Exception inner) : base(msg, inner) { }
    }
}
