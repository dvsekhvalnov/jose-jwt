using System.Text;
using Jose;
using Xunit;

namespace UnitTests
{
    public class AesGcmTest
    {
        private static readonly byte[] aes128Key = new byte[] { 194, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133 };

        [Fact]
        public void Encrypt()
        {
            //given
            byte[] iv = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
            byte[] aad = Encoding.UTF8.GetBytes("secre");
            byte[] text = Encoding.UTF8.GetBytes("hellow aes !");

            //when
            byte[][] test = AesGcm.Encrypt(aes128Key, iv, aad, text);

            //then
            Assert.Equal(new byte[] { 245, 242, 160, 166, 250, 62, 102, 211, 158, 42, 62, 73 }, test[0]);
            Assert.Equal(new byte[] { 195, 69, 216, 140, 118, 58, 48, 131, 47, 225, 205, 198, 78, 12, 180, 76 }, test[1]);
        }

        [Fact]
        public void Decrypt()
        {
            //given
            byte[] iv = { 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };
            byte[] tag = { 121, 235, 93, 169, 185, 192, 202, 230, 130, 37, 35, 135, 46, 129, 168, 104 };
            byte[] cipher = { 33, 6, 206, 1, 182, 114, 131, 218, 124, 60 };
            byte[] aad = Encoding.UTF8.GetBytes("top secret");

            //when
            byte[] test = AesGcm.Decrypt(aes128Key, iv, aad, cipher, tag);

            //then
            Assert.Equal(Encoding.UTF8.GetBytes("decrypt me"), test);
        }
    }
}