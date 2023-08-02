using System;

namespace LibSnaffle.Errors
{
    /// <summary>
    /// Represents an Exception to be used when a SYSVOL fails to be parsed.
    /// </summary>
    public class SysvolException : Exception
    {
        public SysvolException(string msg) : base(msg) { }
        public SysvolException(string msg, Exception inner) : base(msg, inner) { }
    }
}
