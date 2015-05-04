using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace Owin.Security.ActiveDirectoryLDAP
{
    public static class Test
    {
        public static void derp(byte[] times)
        {
            if (times == null)
                return;

            Array.Resize<byte>(ref times, 3 * 7);//Make sure the array has 3 bytes for every day of the week.
            for (var i = 0; i < 3 * 7; i += 3)
            {
                //0, 3, 6, 9, 12, 15, 18, 21
                var day = (DayOfWeek)(i / 3);
                
                byte[] bytes = { times[i + 0], times[i + 1], times[i + 2], 0 };
                if (!BitConverter.IsLittleEndian)//opposite?
                    Array.Reverse(bytes);
                var bits = BitConverter.ToInt32(bytes, 0);

                if (bits == 0)//nothing on this day
                    continue;

                if ((bits & 1 << 0) > 0)//12am
                    Debug.WriteLine(day.ToString() + " at 12am");
                if ((bits & 1 << 1) > 0)//1am
                    Debug.WriteLine(day.ToString() + " at 1am");
                if ((bits & 1 << 2) > 0)//2am
                    Debug.WriteLine(day.ToString() + " at 2am");
                if ((bits & 1 << 3) > 0)//3am
                    Debug.WriteLine(day.ToString() + " at 3am");
                if ((bits & 1 << 4) > 0)//4am
                    Debug.WriteLine(day.ToString() + " at 4am");
                if ((bits & 1 << 5) > 0)//5am
                    Debug.WriteLine(day.ToString() + " at 5am");
                if ((bits & 1 << 6) > 0)//6am
                    Debug.WriteLine(day.ToString() + " at 6am");
                if ((bits & 1 << 7) > 0)//7am
                    Debug.WriteLine(day.ToString() + " at 7am");
                if ((bits & 1 << 8) > 0)//8am
                    Debug.WriteLine(day.ToString() + " at 8am");
                if ((bits & 1 << 9) > 0)//9am
                    Debug.WriteLine(day.ToString() + " at 9am");
                if ((bits & 1 << 10) > 0)//10am
                    Debug.WriteLine(day.ToString() + " at 10am");
                if ((bits & 1 << 11) > 0)//11am
                    Debug.WriteLine(day.ToString() + " at 11am");
                if ((bits & 1 << 12) > 0)//12pm
                    Debug.WriteLine(day.ToString() + " at 12pm");
                if ((bits & 1 << 13) > 0)//1pm
                    Debug.WriteLine(day.ToString() + " at 1pm");
                if ((bits & 1 << 14) > 0)//2pm
                    Debug.WriteLine(day.ToString() + " at 2pm");
                if ((bits & 1 << 15) > 0)//3pm
                    Debug.WriteLine(day.ToString() + " at 3pm");
                if ((bits & 1 << 16) > 0)//4pm
                    Debug.WriteLine(day.ToString() + " at 4pm");
                if ((bits & 1 << 17) > 0)//5pm
                    Debug.WriteLine(day.ToString() + " at 5pm");
                if ((bits & 1 << 18) > 0)//6pm
                    Debug.WriteLine(day.ToString() + " at 6pm");
                if ((bits & 1 << 19) > 0)//7pm
                    Debug.WriteLine(day.ToString() + " at 7pm");
                if ((bits & 1 << 20) > 0)//8pm
                    Debug.WriteLine(day.ToString() + " at 8pm");
                if ((bits & 1 << 21) > 0)//9pm
                    Debug.WriteLine(day.ToString() + " at 9pm");
                if ((bits & 1 << 22) > 0)//10pm
                    Debug.WriteLine(day.ToString() + " at 10pm");
                if ((bits & 1 << 23) > 0)//11pm
                    Debug.WriteLine(day.ToString() + " at 11pm");



            }

            var o = 3;
        }
    }

    public static class PermittedLogonTimes
    {
        /// <summary>
        /// Calculate the logon times based on an Active Directory byte mask
        /// </summary>
        /// <param name="byteMask">Active Directory byte mask</param>
        /// <returns>List of LogonTime objects to signify allows times</returns>
        public static List<LogonTime> GetLogonTimes(byte[] byteMask)
        {
            var zone = TimeZoneInfo.FindSystemTimeZoneById(TimeZone.CurrentTimeZone.StandardName);
            return GetLogonTimes(byteMask, zone);
        }

        /// <summary>
        /// Calculate the logon times based on an Active Directory byte mask
        /// </summary>
        /// <param name="byteMask">Active Directory byte mask</param>
        /// <param name="timeZone">Time zone to convert to</param>
        /// <returns>List of LogonTime objects to signify allows times</returns>
        public static List<LogonTime> GetLogonTimes(byte[] byteMask, TimeZoneInfo timeZone)
        {
            var hours = MarkHours(byteMask);
            timeZone = TimeZoneInfo.Utc;

            return ConvertToLogonTime(hours, (timeZone.BaseUtcOffset.Hours));
        }

        /// <summary>
        /// Initialize an array for every hour of everyday for a week
        /// </summary>
        /// <remarks>
        /// Each slot represents an hour of a day.  Ex. [0]=sunday 12am GMT, [1]=sunday 1am GMT ...
        /// During calculations based on time offset, hours will shift, Ex. [0]=sunday 1am GMT-1, [1]=sunday 2am GMT-1 ...
        /// PST Calcuation (GMT -8): [9]=sunday 8am, [1]=sunday 9am
        /// All values will be stored with an offset relative to GMT
        /// </remarks>
        /// <returns></returns>
        private static bool[] InitializeTimeArray()
        {
            return Enumerable.Repeat<bool>(false, 24 * 7).ToArray();
        }

        /// <summary>
        /// Fills in an hour array based on bytemask
        /// </summary>
        /// <param name="byteMask"></param>
        private static bool[] MarkHours(byte[] byteMask)
        {
            var hours = InitializeTimeArray();

            for (var i = 0; i < byteMask.Length; i++)
            {
                ParseBlock(byteMask[i], hours, i * 8);
            }

            return hours;
        }

        /// <summary>
        /// Convert the byte block back into the array
        /// </summary>
        /// <param name="block"></param>
        /// <param name="hours"></param>
        /// <param name="index"></param>
        private static void ParseBlock(byte block, bool[] hours, int index)
        {
            var value = block;
            //var value = (int)block;

            if ((value & 1 << 7) > 0)
                hours[index + 7] = true;
            if ((value & 1 << 6) > 0)
                hours[index + 6] = true;
            if ((value & 1 << 5) > 0)
                hours[index + 5] = true;
            if ((value & 1 << 4) > 0)
                hours[index + 4] = true;
            if ((value & 1 << 3) > 0)
                hours[index + 3] = true;
            if ((value & 1 << 2) > 0)
                hours[index + 2] = true;
            if ((value & 1 << 1) > 0)
                hours[index + 1] = true;
            if ((value & 1 << 0) > 0)
                hours[index + 0] = true;
        }

        private static List<LogonTime> ConvertToLogonTime(bool[] hours, int offset)
        {
            var ltimes = new List<LogonTime>();

            int? begin = null, end = null;

            for (var i = 0; i < hours.Length; i++)
            {
                var index = i + (-1) * offset;

                // shifts over begging, loop back to the end
                if (index < 0)
                {
                    index = hours.Length + index;
                }
                // shifts over end, start back from beginning of array
                else if (index >= hours.Length)
                {
                    index = index - hours.Length;
                }

                if (!begin.HasValue && hours[index])
                {
                    begin = CalculateHour(index, offset);
                }
                else if (begin.HasValue && !hours[index])
                {
                    end = CalculateHour(index, offset);

                    // save the day
                    ltimes.Add(new LogonTime(CalculateDay(index, offset), new DateTime(2011, 1, 1, begin.Value, 0, 0), new DateTime(2011, 1, 1, end.Value, 0, 0)));

                    begin = null;
                    end = null;
                }
            }

            return ltimes;
        }

        private static int CalculateHour(int index, int offset)
        {
            var hour = index + offset;
            hour = hour % 24;

            return hour;
        }

        private static DayOfWeek CalculateDay(int index, int offset)
        {
            var day = Math.Floor((decimal)(index + offset) / 24);

            return (DayOfWeek)day;
        }
    }

    public class LogonTime
    {
        public DayOfWeek DayOfWeek { get; set; }
        public DateTime BeginTime { get; set; }
        public DateTime EndTime { get; set; }

        public int TimeZoneOffSet { get; set; }

        public LogonTime(DayOfWeek dayOfWeek, DateTime beginTime, DateTime endTime)
        {
            DayOfWeek = dayOfWeek;
            BeginTime = beginTime;
            EndTime = endTime;

            SetOffset(TimeZoneInfo.FindSystemTimeZoneById(TimeZone.CurrentTimeZone.StandardName));
            ValidateTimes();
        }

        public LogonTime(DayOfWeek dayOfWeek, TimeSpan begin, TimeSpan end)
        {
            DayOfWeek = dayOfWeek;
            BeginTime = new DateTime(begin.Ticks);
            EndTime = new DateTime(end.Ticks);

            SetOffset(TimeZoneInfo.FindSystemTimeZoneById(TimeZone.CurrentTimeZone.StandardName));
            ValidateTimes();
        }

        public LogonTime(DayOfWeek dayOfWeek, DateTime beginTime, DateTime endTime, TimeZoneInfo timeZone)
        {
            DayOfWeek = dayOfWeek;
            BeginTime = beginTime;
            EndTime = endTime;

            SetOffset(timeZone);
            ValidateTimes();
        }

        public LogonTime(DayOfWeek dayOfWeek, TimeSpan begin, TimeSpan end, TimeZoneInfo timeZone)
        {
            DayOfWeek = dayOfWeek;
            BeginTime = new DateTime(begin.Ticks);
            EndTime = new DateTime(end.Ticks);

            SetOffset(timeZone);
            ValidateTimes();
        }

        private void SetOffset(TimeZoneInfo timeZone)
        {
            TimeZoneOffSet = (-1) * (timeZone.BaseUtcOffset.Hours);
            //TimeZoneOffSet = timeZone.IsDaylightSavingTime(DateTime.Now) ? (-1) * (timeZone.GetUtcOffset(DateTime.Now).Hours - 1) : (-1)*(timeZone.GetUtcOffset(DateTime.Now).Hours);
        }

        private void ValidateTimes()
        {
            if (EndTime.Hour < BeginTime.Hour)
            {
                throw new ArgumentException("Begin time cannot be after End time.");
            }
        }
    }
}
