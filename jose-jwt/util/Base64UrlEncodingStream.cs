using System;
using System.IO;

namespace Jose
{
    // Streaming Base64Url encoder
    public class Base64UrlEncodingStream : Stream
    {
        private readonly Stream source;
        private readonly byte[] inBuf;
        private readonly byte[] outBuf;
        private static readonly byte[] Base64UrlAlphabet = System.Text.Encoding.ASCII.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");
        private const int DefaultBufferSize = 12 * 1024; // 12 KB, covers most JSON/XML payloads
        private int outPos, outLen;
        private bool finished;

        public Base64UrlEncodingStream(Stream source)
            : this(source, DefaultBufferSize)
        {
        }

        public Base64UrlEncodingStream(Stream source, int bufferSize)
        {
            this.source = source;
            if (source.CanSeek) source.Position = 0;

            if (bufferSize <= 0)
                throw new ArgumentOutOfRangeException(nameof(bufferSize), "Buffer size must be positive.");

            int alignedSize = bufferSize % 3 == 0 ? bufferSize : bufferSize + (3 - bufferSize % 3);
            inBuf = new byte[alignedSize];
            outBuf = new byte[(alignedSize / 3) * 4];
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
                    int toCopy = Math.Min(outLen - outPos, count - written);
                    Buffer.BlockCopy(outBuf, outPos, buffer, offset + written, toCopy);
                    outPos += toCopy;
                    written += toCopy;
                    continue;
                }

                // Read as much as possible, up to buffer size
                int read = source.Read(inBuf, 0, inBuf.Length);
                if (read == 0)
                {
                    finished = true;
                    break;
                }

                // Manually encode to Base64Url directly into the byte buffer
                int fullGroups = read / 3;
                int remainder = read % 3;
                int inputIndex = 0;
                int outputIndex = 0;

                for (int i = 0; i < fullGroups; i++)
                {
                    int b0 = inBuf[inputIndex++];
                    int b1 = inBuf[inputIndex++];
                    int b2 = inBuf[inputIndex++];

                    outBuf[outputIndex++] = Base64UrlAlphabet[b0 >> 2];
                    outBuf[outputIndex++] = Base64UrlAlphabet[((b0 & 0x03) << 4) | (b1 >> 4)];
                    outBuf[outputIndex++] = Base64UrlAlphabet[((b1 & 0x0F) << 2) | (b2 >> 6)];
                    outBuf[outputIndex++] = Base64UrlAlphabet[b2 & 0x3F];
                }

                if (remainder == 1)
                {
                    int b0 = inBuf[inputIndex++];
                    outBuf[outputIndex++] = Base64UrlAlphabet[b0 >> 2];
                    outBuf[outputIndex++] = Base64UrlAlphabet[(b0 & 0x03) << 4];
                }
                else if (remainder == 2)
                {
                    int b0 = inBuf[inputIndex++];
                    int b1 = inBuf[inputIndex++];
                    outBuf[outputIndex++] = Base64UrlAlphabet[b0 >> 2];
                    outBuf[outputIndex++] = Base64UrlAlphabet[((b0 & 0x03) << 4) | (b1 >> 4)];
                    outBuf[outputIndex++] = Base64UrlAlphabet[(b1 & 0x0F) << 2];
                }

                outLen = outputIndex;
                outPos = 0;
            }
            return written;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}