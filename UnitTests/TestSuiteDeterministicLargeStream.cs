using System;
using System.IO;
using System.Linq;

namespace UnitTests
{
    // Deterministically generates a large payload without allocating the entire buffer in memory.
    public class DeterministicLargeStream : Stream
    {
        private readonly long length;
        private long position;
        private long maxPosition;

        public DeterministicLargeStream(long length)
        {
            if (length < 0)
                throw new ArgumentOutOfRangeException(nameof(length));

            this.length = length;
            position = 0;
            maxPosition = 0;
        }

        public long BytesServed => maxPosition;

        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => length;

        public override long Position
        {
            get => position;
            set
            {
                if (value < 0 || value > length)
                    throw new ArgumentOutOfRangeException(nameof(value));

                position = value;
            }
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (buffer == null)
                throw new ArgumentNullException(nameof(buffer));
            if (offset < 0)
                throw new ArgumentOutOfRangeException(nameof(offset));
            if (count < 0)
                throw new ArgumentOutOfRangeException(nameof(count));
            if (buffer.Length - offset < count)
                throw new ArgumentException("Invalid offset and count combination.", nameof(buffer));

            if (position >= length || count == 0)
                return 0;

            int toRead = (int)Math.Min(count, length - position);

            var pattern = Enumerable.Range(byte.MinValue, byte.MaxValue + 1).Select(i => (byte)i).ToArray();
            int patternIndex = (int)(position % pattern.Length);
            int remaining = toRead;
            int written = 0;

            while (remaining > 0)
            {
                int copy = Math.Min(pattern.Length - patternIndex, remaining);
                Buffer.BlockCopy(pattern, patternIndex, buffer, offset + written, copy);
                written += copy;
                remaining -= copy;
                patternIndex = 0;
            }

            position += toRead;
            if (position > maxPosition)
                maxPosition = position;

            return toRead;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            long target = origin switch
            {
                SeekOrigin.Begin => offset,
                SeekOrigin.Current => position + offset,
                SeekOrigin.End => length + offset,
                _ => throw new ArgumentOutOfRangeException(nameof(origin))
            };

            if (target < 0 || target > length)
                throw new ArgumentOutOfRangeException(nameof(offset));

            position = target;
            return position;
        }

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
