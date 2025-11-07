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
            // Header part
            var headerBytes = Encoding.UTF8.GetBytes(Base64Url.Encode(header));
            var dot = Encoding.UTF8.GetBytes(".");

            // Build a sequence of streams: header, ".", payload, ".", other parts joined by "."
            var streams = new List<Stream>
            {
                new MemoryStream(headerBytes, writable: false),
                new MemoryStream(dot, writable: false)
            };

            // Payload part
            Stream payloadStream = encodePayload
                ? new Base64UrlEncodingStream(payload)
                : payload;

            if (payload.CanSeek)
                payload.Position = 0;

            streams.Add(payloadStream);
            streams.Add(new MemoryStream(dot, writable: false));

            // Other parts
            for (int i = 0; i < other.Length; i++)
            {
                var test = Base64Url.Encode(other[i]);

                if (encodePayload)
                    streams.Add(new Base64UrlEncodingStream(new MemoryStream(other[i], writable: false)));
                else
                    streams.Add(new MemoryStream(other[i], writable: false));

                if (i < other.Length - 1)
                    streams.Add(new MemoryStream(dot, writable: false));
            }

            return new ConcatenatedStream(streams);
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