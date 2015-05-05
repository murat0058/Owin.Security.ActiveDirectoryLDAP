using System;

namespace Owin.Security.ActiveDirectoryLDAP
{
    public enum SerializationFormat : short
    {
        Json = 0,
        Xml = 1
    }

    public enum LogonTimeUnit : short
    {
        Days,
        Hours,
        Minutes
    }
}
