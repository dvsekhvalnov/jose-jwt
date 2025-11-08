using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Jose
{
    public static class Compact
    {
        public static string Serialize(params byte[][] parts)
        {
            var builder = new StringBuilder();

            foreach (var part in parts)
            {
                builder.Append(Base64Url.Encode(part)).Append(".");
            }

            builder.Remove(builder.Length - 1, 1);

            return builder.ToString();
        }

        public static Stream Serialize(byte[] header, Stream payload, bool encodePayload, params byte[][] other)
        {
            var dotBytes = Encoding.UTF8.GetBytes(".");
            var streams = new List<Stream>();

            // header
            streams.Add(new MemoryStream(Encoding.UTF8.GetBytes(Base64Url.Encode(header)), false));
            streams.Add(new MemoryStream(dotBytes, false));

            // payload
            payload.Position = 0;
            streams.Add(encodePayload ? new Base64UrlEncodingStream(payload) : payload);

            if (other.Length > 0)
            {
                streams.Add(new MemoryStream(dotBytes, false));
                for (int i = 0; i < other.Length; i++)
                {
                    streams.Add(new MemoryStream(Encoding.UTF8.GetBytes(Base64Url.Encode(other[i])), false));
                    if (i < other.Length - 1)
                        streams.Add(new MemoryStream(dotBytes, false));
                }
            }

            // Keep original payload stream undisposed for caller reuse
            return new ConcatenatedStream(streams, payload);
        }

        public static byte[][] Parse(string token)
        {
            if (token == null)
                throw new ArgumentNullException(nameof(token));

            string[] parts = token.Split('.');

            var result = new byte[parts.Length][];

            for (int i = 0; i < parts.Length; i++)
            {
                result[i] = Base64Url.Decode(parts[i]);
            }

            return result;
        }

        public static Iterator Iterate(string token)
        {
            if (token == null)
                throw new ArgumentNullException(nameof(token));

            return new Iterator(token, token.Split('.'));
        }

        public class Iterator
        {
            private string token;
            private string[] parts;
            private int current;

            public Iterator(string token, string[] parts)
            {
                this.token = token;
                this.parts = parts;
                this.current = 0;
            }

            public int Count
            {
                get { return parts.Length; }
            }

            public byte[] Next(bool decode = true)
            {
                if (current < parts.Length)
                {
                    string part = parts[current++];

                    return decode ? Base64Url.Decode(part) : Encoding.UTF8.GetBytes(part);
                }

                return null;
            }

            public string Token
            {
                get { return token; }
            }
        }
    }
}