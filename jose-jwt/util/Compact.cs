using System;
using System.Text;

namespace Jose
{
    public class Compact
    {
        public static string Serialize(params byte[][] parts)
        {
            var builder=new StringBuilder();

            foreach (var part in parts)
            {
                builder.Append(Base64Url.Encode(part)).Append(".");
            }

            builder.Remove(builder.Length - 1,1);

            return builder.ToString();
        }

        public static byte[][] Parse(string token)
        {
            string[] parts = token.Split('.');

            var result = new byte[parts.Length][];

            for (int i = 0; i < parts.Length; i++)
            {
                result[i] = Base64Url.Decode(parts[i]);
            }

            return result;
        }
    }
}