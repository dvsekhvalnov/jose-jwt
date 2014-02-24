using System;

namespace Jose
{
    public class Ensure
    {
        public static void IsEmpty(byte[] arr, string msg)
        {
            if(arr.Length!=0)
                throw new ArgumentException(msg);
        }

        public static T Type<T>(object obj, string msg)
        {
            if (!(obj is T))
                throw new ArgumentException(msg);

            return (T) obj;
        }

        public static void IsNull(object key, string msg)
        {
            if (key != null)
                throw new ArgumentException(msg);
        }

        public static void BitSize(byte[] key, int expectedSize, string msg)
        {
            if(expectedSize!=key.Length * 8)
                throw new ArgumentException(msg);
        }
    }
}