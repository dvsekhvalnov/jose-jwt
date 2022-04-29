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
            Assert.Equal(new byte[] { 0, 1, 2, 3, 4 }, Arrays.FirstHalf(data));
        }

        [Fact]
        public void SecondHalf()
        {
            //given
            byte[] data = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

            //then
            Assert.Equal(new byte[] { 5, 6, 7, 8, 9 }, Arrays.SecondHalf(data));
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
            Assert.Equal(new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }, Arrays.Concat(zeros, first, second, third, forth));
        }

        [Fact]
        public void Slice()
        {
            //given
            byte[] data = { 0, 1, 2, 3, 4, 5, 6, 7, 8 };

            //when
            byte[][] test = Arrays.Slice(data, 3);

            //then
            Assert.Equal(new byte[] { 0, 1, 2 }, test[0]);
            Assert.Equal(new byte[] { 3, 4, 5 }, test[1]);
            Assert.Equal(new byte[] { 6, 7, 8 }, test[2]);
        }

        [Fact]
        public void LongToBytes()
        {
            Assert.Equal(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF }, Arrays.LongToBytes(255));
            Assert.Equal(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE }, Arrays.LongToBytes(-2));
        }

        [Fact]
        public void BytesToLong()
        {
            Assert.Equal(255, Arrays.BytesToLong(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF }));
            Assert.Equal(-2, Arrays.BytesToLong(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE }));
        }

        [Fact]
        public void IntToBytes()
        {
            Assert.Equal(new byte[] { 0x00, 0x00, 0x00, 0xFF }, Arrays.IntToBytes(255));
            Assert.Equal(new byte[] { 0xFF, 0xFF, 0xFF, 0xFE }, Arrays.IntToBytes(-2));
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
            Assert.Equal(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, test);
            Assert.Equal(new byte[] { 0x00, 0xFF, 0x0F, 0xF0, 0xAA, 0x55, 0x44, 0x33 }, test2);
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
            Assert.Equal(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, test);
            Assert.Equal(new byte[] { 0x00, 0xFF, 0x0F, 0xF0, 0xAA, 0x55, 0x44, 0x33 }, test2);
        }

        [Fact]
        public void LeftmostBits()
        {
            //given
            byte[] data = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

            //then
            Assert.Equal(new byte[] { 0, 1 }, Arrays.LeftmostBits(data, 16));
            Assert.Equal(new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8 }, Arrays.LeftmostBits(data, 72));
        }

        [Fact]
        public void RightmostBits()
        {
            //given
            byte[] data = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

            //then
            Assert.Equal(new byte[] { 8, 9 }, Arrays.RightmostBits(data, 16));
            Assert.Equal(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 }, Arrays.RightmostBits(data, 72));
        }
    }
}