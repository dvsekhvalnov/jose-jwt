using System;
using System.IO;

namespace Jose
{
    // Streaming Base64Url encoder
    public class Base64UrlEncodingStream : Stream
    {
        private readonly Stream source;
        private const int BufferBlockSize = 3072; // 3 KB, divisible by 3 (3072 / 3 = 1024)
        private readonly byte[] inBuf = new byte[BufferBlockSize];
        private readonly byte[] outBuf = new byte[(BufferBlockSize / 3) * 4]; // 4096 bytes
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
            // Reusable char buffer for base64url encoding (max 4 chars per 3 bytes * chunk)
            char[] charBuf = new char[(BufferBlockSize / 3) * 4];
            while (written < count && !finished)
            {
                if (outPos < outLen)
                {
                    buffer[offset + written++] = outBuf[outPos++];
                    continue;
                }

                // Read as much as possible, up to buffer size
                int read = source.Read(inBuf, 0, inBuf.Length);
                if (read == 0)
                {
                    finished = true;
                    break;
                }

                // Convert to base64 chars directly
                int b64Len = Convert.ToBase64CharArray(inBuf, 0, read, charBuf, 0);

                // Remove padding and apply base64url replacements in-place
                int urlLen = b64Len;

                // Remove any trailing '=' padding
                while (urlLen > 0 && charBuf[urlLen - 1] == '=')
                {
                    urlLen--;
                }

                // Convert to Base64Url: replace '+' with '-', '/' with '_'
                for (int i = 0; i < urlLen; i++)
                {
                    char c = charBuf[i];
                    if (c == '+')
                        c = '-';
                    else if (c == '/')
                        c = '_';
                    outBuf[i] = (byte)c;
                }

                outLen = urlLen;
                outPos = 0;
            }
            return written;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}