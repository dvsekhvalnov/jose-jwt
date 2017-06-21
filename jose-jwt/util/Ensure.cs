using System;
using System.Collections.Generic;
using System.Linq;

namespace Jose
{
    public class Ensure
    {
        public static void IsEmpty(byte[] arr, string msg, params object[] args)
        {
            if(arr.Length!=0)
                throw new ArgumentException(msg);
        }

        public static T Type<T>(object obj, string msg, params object[] args)
        {
            if (!(obj is T))
                throw new ArgumentException(msg);

            return (T) obj;
        }

        public static void IsNull(object key, string msg, params object[] args)
        {
            if (key != null)
                throw new ArgumentException(msg);
        }

        public static void BitSize(byte[] array, long expectedSize, string msg, params object[] args)
        {
            if(expectedSize != array.Length * 8L)
                throw new ArgumentException(string.Format(msg,args));
        }

        public static void BitSize(int actualSize, int expectedSize, string msg)
        {
            if(expectedSize!=actualSize)
                throw new ArgumentException(msg);
        }

        public static void IsNotEmpty(string arg, string msg, params object[] args)
        {
            if(string.IsNullOrWhiteSpace(arg))   
                throw new ArgumentException(msg);
        }

        public static void Divisible(int arg, int divisor, string msg, params object[] args)
        {
            if(arg % divisor !=0)
                throw new ArgumentException(string.Format(msg,args));
        }

        public static void MinValue(long arg, long min, string msg, params object[] args)
        {
            if(arg < min)
                throw new ArgumentException(string.Format(msg,args));
        }

        public static void MaxValue(int arg, long max, string msg, params object[] args)
        {
            if(arg > max)
                throw new ArgumentException(string.Format(msg,args));
        }

        public static void MinBitSize(byte[] arr, long minBitSize, string msg, params object[] args)
        {
            MinValue(arr.Length * 8L, minBitSize, msg, args);
        }

        public static void Contains(IDictionary<string, object> dict, string[] keys, string msg, params  object[] args)
        {
            if (keys.Any(key => !dict.ContainsKey(key)))
                throw new ArgumentException(string.Format(msg, args));
        }

        public static void SameSize(byte[] left, byte[] right, string msg, params object[] args)
        {
            if(left.Length!=right.Length)
                throw new ArgumentException(string.Format(msg, args));
        }
    }
}