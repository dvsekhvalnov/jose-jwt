using System;
using System.Linq;
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
                builder.Append(Base64UrlEncode(part)).Append(".");
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
                result[i] = Base64UrlDecode(parts[i]);
            }

            return result;
        }

        public static string Base64UrlEncode(byte[] input)
        {
            var output = Convert.ToBase64String(input);
            output = output.Split('=')[0]; // Remove any trailing '='s
            output = output.Replace('+', '-'); // 62nd char of encoding
            output = output.Replace('/', '_'); // 63rd char of encoding
            return output;
        }

        public static byte[] Base64UrlDecode(string input)
        {
            var output = input;
            output = output.Replace('-', '+'); // 62nd char of encoding
            output = output.Replace('_', '/'); // 63rd char of encoding
            switch (output.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 2: output += "=="; break; // Two pad chars
                case 3: output += "="; break; // One pad char
                default: throw new System.Exception("Illegal base64url string!");
            }
            var converted = Convert.FromBase64String(output); // Standard base64 decoder
            return converted;
        }


    }
}