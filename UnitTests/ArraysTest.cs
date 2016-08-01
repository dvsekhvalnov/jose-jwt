using Jose;
using Xunit;

namespace UnitTests
{
    public class ArraysTest
    {
        [Fact]
        public void FirstHalf()
        {
            //given
            byte[] data = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

            //then
            Assert.Equal(Arrays.FirstHalf(data), new byte[] { 0, 1, 2, 3, 4 });
        }

        [Fact]
        public void SecondHalf()
        {
            //given
            byte[] data = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

            //then
            Assert.Equal(Arrays.SecondHalf(data), new byte[] { 5, 6, 7, 8, 9 });
        }

        [Fact]
        public void Concat()
        {
            //given
            byte[] zeros = null;
            byte[] first = { 0, 1 };
            byte[] second = { 2, 3, 4, 5 };
            byte[] third = { 6, 7, 8, 9 };
            byte[] forth = null;

            //then
            Assert.Equal(Arrays.Concat(zeros, first, second, third, forth), new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 });
        }

        [Fact]
        public void Slice()
        {
            //given
            byte[] data = { 0, 1, 2, 3, 4, 5, 6, 7, 8 };

            //when
            byte[][] test = Arrays.Slice(data, 3);

            //then
            Assert.Equal(test[0], new byte[] { 0, 1, 2 });
            Assert.Equal(test[1], new byte[] { 3, 4, 5 });
            Assert.Equal(test[2], new byte[] { 6, 7, 8 });
        }

        [Fact]
        public void LongToBytes()
        {
            Assert.Equal(Arrays.LongToBytes(255), new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF });
            Assert.Equal(Arrays.LongToBytes(-2), new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE });
        }

        [Fact]
        public void BytesToLong()
        {
            Assert.Equal(Arrays.BytesToLong(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF }), 255);
            Assert.Equal(Arrays.BytesToLong(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE }), -2);
        }

        [Fact]
        public void IntToBytes()
        {
            Assert.Equal(Arrays.IntToBytes(255), new byte[] { 0x00, 0x00, 0x00, 0xFF });
            Assert.Equal(Arrays.IntToBytes(-2), new byte[] { 0xFF, 0xFF, 0xFF, 0xFE });
        }

        [Fact]
        public void Xor()
        {
            //given
            byte[] data = { 0xFF, 0x00, 0xF0, 0x0F, 0x55, 0xAA, 0xBB, 0xCC };

            //when
            byte[] test = Arrays.Xor(data, 0x00FF0FF0AA554433);
            byte[] test2 = Arrays.Xor(data, -1);

            //then
            Assert.Equal(test, new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });
            Assert.Equal(test2, new byte[] { 0x00, 0xFF, 0x0F, 0xF0, 0xAA, 0x55, 0x44, 0x33 });
        }

        [Fact]
        public void XorArrays()
        {
            //given
            byte[] data = { 0xFF, 0x00, 0xF0, 0x0F, 0x55, 0xAA, 0xBB, 0xCC };

            //when
            byte[] test = Arrays.Xor(data, new byte[] { 0x00, 0xFF, 0x0F, 0xF0, 0xAA, 0x55, 0x44, 0x33 });
            byte[] test2 = Arrays.Xor(data, new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });

            //then
            Assert.Equal(test, new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });
            Assert.Equal(test2, new byte[] { 0x00, 0xFF, 0x0F, 0xF0, 0xAA, 0x55, 0x44, 0x33 });
        }

        [Fact]
        public void LeftmostBits()
        {
            //given
            byte[] data = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

            //then
            Assert.Equal(Arrays.LeftmostBits(data, 16), new byte[] { 0, 1 });
            Assert.Equal(Arrays.LeftmostBits(data, 72), new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8 });
        }

        [Fact]
        public void RightmostBits()
        {
            //given
            byte[] data = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

            //then
            Assert.Equal(Arrays.RightmostBits(data, 16), new byte[] { 8, 9 });
            Assert.Equal(Arrays.RightmostBits(data, 72), new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 });
        }
    }
}