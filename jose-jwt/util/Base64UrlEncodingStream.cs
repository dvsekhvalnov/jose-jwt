using System;
using System.IO;

namespace Jose
{
    // Streaming Base64Url encoder
    public class Base64UrlEncodingStream : Stream
    {
        private readonly Stream source;
        private readonly byte[] inBuf = new byte[3];
        private readonly byte[] outBuf = new byte[4];
        private int outPos, outLen;
        private bool finished;

        public Base64UrlEncodingStream(Stream source)
        {
            this.source = source;
            if (source.CanSeek) source.Position = 0;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int written = 0;
            while (written < count && !finished)
            {
                if (outPos < outLen)
                {
                    buffer[offset + written++] = outBuf[outPos++];
                    continue;
                }

                int read = source.Read(inBuf, 0, 3);
                if (read == 0)
                {
                    finished = true;
                    break;
                }

                string b64 = Convert.ToBase64String(inBuf, 0, read)
                    .TrimEnd('=')
                    .Replace('+', '-')
                    .Replace('/', '_');

                outLen = b64.Length;
                for (int i = 0; i < outLen; i++)
                    outBuf[i] = (byte)b64[i];

                outPos = 0;
            }
            return written;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}