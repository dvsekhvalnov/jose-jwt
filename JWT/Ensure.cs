using System;

namespace Json
{
    public class Ensure
    {
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
    }
}