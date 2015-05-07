using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Claims;
using System.Text;

namespace Owin.Security.ActiveDirectoryLDAP
{
    //Not sure if this applies to our return values
    //https://msdn.microsoft.com/en-us/library/aa394221%28v=vs.85%29.aspx #LogonHours
    //PermittedLogonTimes are stored as utc
    //Each bit represents a UnitsPerWeek unit (can this ever be not-hours on our return? if so how can we tell what it is)
    //https://msdn.microsoft.com/en-us/library/cc245621.aspx
    //TODO: Handle TimeZones functionality that was present in the 386ffcb5c355eb2fd8f7edbf667f4ff89c5b9138 tree?

    //I'm not sure if this can be anything but hours on a UserPrincipal.PermittedLogonTimes
    //or if this is even a reliable way to tell, can we get the actual UnitsPerWeek from someplace?
    //if (times.Length == 1)// (7*1)/8
    //    ;//7 bits, each bit is a day UnitsPerWeek, 00:00:00 to 23:59:59
    //if (times.Length == 21)// (7*24)/8
    //    ;//168 bits, each bit is an hour UnitsPerWeek, 00:00 to 59:59
    //if (times.Length == 1260)// (7*24*60)/8
    //    ;//10080 bits, each bit is a minute UnitsPerWeek, 00 to 59

    [DataContract(Namespace = "http://schemas.wustl.edu/ws/2015/04/logontimes")]
    public class LogonTimes
    {
        //Dictionary? This will probably be small enough to not matter, but it may be a little faster.
        [DataMember]
        private IList<LogonTime> Times = new List<LogonTime>();

        public void Add(LogonTime logonTime)
        {
            Times.Add(logonTime);
        }

        public void Add(DayOfWeek dayOfWeek, LogonTimeUnit unit, uint startPeriod)
        {
            Times.Add(new LogonTime(dayOfWeek, unit, startPeriod));
        }

        public bool CanLogon(DateTime current)
        {
            return Times.Any(_ => _.CanLogon(current));
        }

        /// <summary>
        /// Parse a PermittedLogonTimes byte array into a LogonTimes object.
        /// </summary>
        /// <param name="times">Byte array of UTC logon times.</param>
        /// <returns>A LogonTimes object of the given permitted times.</returns>
        public static LogonTimes PermittedLogonTimes(byte[] times)
        {
            if (times == null)
                return null;//All?

            var logonTimes = new LogonTimes();

            //Each day gets 3 bytes of hour flags, make sure the array is long enough to loop through all of them.
            Array.Resize<byte>(ref times, 3 * 7);
            for (var i = 0; i < 3 * 7; i += 3)
            {
                byte[] bytes = { times[i + 0], times[i + 1], times[i + 2], 0 };//Aggregate all of the hour flags.
                if (!BitConverter.IsLittleEndian)//Make sure they bytes are in the proper order to make into one large set of flags.
                    Array.Reverse(bytes);
                var bits = BitConverter.ToInt32(bytes, 0);//Convert the 3 bytes of flags into one set of flags.
                if (bits == 0)//nothing on this day
                    continue;

                //0, 3, 6, 9, 12, 15, 18, 21
                var day = (DayOfWeek)(i / 3);
                for (var j = 0; j < 24; j++)
                {
                    if ((bits & 1 << j) > 0)
                        logonTimes.Add(day, LogonTimeUnit.Hours, (uint)j);
                }
            }

            return logonTimes;
        }

        public static Group FromClaim(Claim claim)
        {
            //return null instead of throwing?
            if (claim.Type != ClaimTypesAD.ActiveDirectoryGroup)
                throw new ArgumentException("Invalid claim type.", "claim");
            //not a great thing to do
            if (claim.Value.StartsWith("{"))
                return FromJson(claim.Value);
            if (claim.Value.StartsWith("<"))
                return FromXml(claim.Value);
            throw new FormatException("Claim value format could not be detected.");
        }

        public static Group FromJson(string json)
        {
            using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(json)))
            {
                stream.Position = 0;
                return new DataContractJsonSerializer(typeof(Group)).ReadObject(stream) as Group;
            }
        }

        public static Group FromXml(string xml)
        {
            using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(xml)))
            {
                stream.Position = 0;
                return new DataContractSerializer(typeof(Group)).ReadObject(stream) as Group;
            }
        }

        public Claim ToClaim(SerializationFormat serializationFormat = SerializationFormat.Json)
        {
            var serialized = serializationFormat == SerializationFormat.Json
                ? this.ToJson()
                : this.ToXml();
            return new Claim(ClaimTypesAD.PermittedLogonTimes, serialized);
        }

        public string ToJson()
        {
            using (var stream = new MemoryStream())
            {
                new DataContractJsonSerializer(typeof(Group)).WriteObject(stream, this);
                return Encoding.UTF8.GetString(stream.ToArray());
            }
        }

        public string ToXml()
        {
            using (var stream = new MemoryStream())
            {
                new DataContractSerializer(typeof(Group)).WriteObject(stream, this);
                return Encoding.UTF8.GetString(stream.ToArray());
            }
        }
    }

    [DataContract(Namespace = "http://schemas.wustl.edu/ws/2015/04/logontime")]
    public class LogonTime
    {
        /// <summary>
        /// The day of the week of the logon period.
        /// </summary>
        [DataMember]
        public DayOfWeek DayOfWeek { get; private set; }
        /// <summary>
        /// The length of the logon period.
        /// </summary>
        [DataMember]
        public TimeSpan LogonPeriod { get; private set; }
        /// <summary>
        /// The minutes after midnight when the logon period starts.
        /// </summary>
        [DataMember]
        public uint StartMinutes { get; private set; }
        
        public LogonTime(DayOfWeek dayOfWeek, LogonTimeUnit unit, uint startPeriod)
        {
            if (unit == LogonTimeUnit.Days && startPeriod > 0)//Just ignore it?
                throw new ArgumentOutOfRangeException("startPeriod", "A day starts at midnight.");
            if (unit == LogonTimeUnit.Hours && startPeriod > 23)
                throw new ArgumentOutOfRangeException("startPeriod", "A day only has 24 hours.");
            if (unit == LogonTimeUnit.Minutes && startPeriod > 1440)
                throw new ArgumentOutOfRangeException("startPeriod", "A day only has 1440 minutes.");

            DayOfWeek = dayOfWeek;

            switch (unit)
            {
                case LogonTimeUnit.Days:
                    LogonPeriod = new TimeSpan(0, 23, 59, 59, 999);//inclusive at both ends
                    StartMinutes = 0;
                    break;
                case LogonTimeUnit.Hours:
                    LogonPeriod = new TimeSpan(0, 0, 59, 59, 999);//inclusive at both ends
                    StartMinutes = startPeriod * 60;
                    break;
                case LogonTimeUnit.Minutes:
                    LogonPeriod = new TimeSpan(0, 0, 0, 59, 999);//inclusive at both ends
                    StartMinutes = startPeriod;
                    break;
            }
        }

        public bool CanLogon(DateTime current)
        {
            var utc = current.ToUniversalTime();
            var day = utc.DayOfWeek;
            var start = utc.Date.AddMinutes(StartMinutes);
            var end = start + LogonPeriod;
            return day == DayOfWeek && start <= utc && utc <= end;
        }
    }
}
