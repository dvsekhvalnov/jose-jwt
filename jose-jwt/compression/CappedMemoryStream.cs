using System;
using System.IO;

namespace Jose
{
    public class CappedMemoryStream : MemoryStream
    {
        private readonly long maxCapacity;

        public CappedMemoryStream(long maxCapacity)
        {
            this.maxCapacity = maxCapacity;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (Length + Math.Min(count, buffer.Length - offset) > maxCapacity)
            {
                throw new CapacityExceededException("Exceeding maximum memory stream size.");
            }

            base.Write(buffer, offset, count);
        }

        public override void WriteByte(byte value)
        {
            if (Length + 1 > maxCapacity)
            {
                throw new CapacityExceededException("Exceeding maximum memory stream size.");
            }

            base.WriteByte(value);
        }
    }
}