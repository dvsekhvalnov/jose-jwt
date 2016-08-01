using Jose;
using NUnit.Framework;

namespace UnitTests
{
    [TestFixture]
    public class AesKeyWrapTest
    {
        [Test]
        public void Wrap_128Key_128Kek()
        {
            //given (Section 4.1)

            //000102030405060708090A0B0C0D0E0F
            byte[] kek = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

            //00112233445566778899AABBCCDDEEFF
            byte[] key = {0,17,34,51,68,85,102,119,136,153,170,187,204,221,238,255};

            //1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5
            byte[] expected = { 31, 166, 139, 10, 129, 18, 180, 71, 174, 243, 75, 216, 251, 90, 123, 130, 157, 62, 134,35, 113, 210, 207, 229};

            //when
            byte[] test = AesKeyWrap.Wrap(key, kek);

            //then
            Assert.That(test,Is.EqualTo(expected));
        }

        [Test]
        public void Unwrap_128key_128kek()
        {
            //given (Section 4.1)

            //000102030405060708090A0B0C0D0E0F
            byte[] kek = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

            //00112233445566778899AABBCCDDEEFF
            byte[] expected = { 0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255 };

            //1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5
            byte[] key = { 31, 166, 139, 10, 129, 18, 180, 71, 174, 243, 75, 216, 251, 90, 123, 130, 157, 62, 134, 35, 113, 210, 207, 229 };

            //when
            byte[] test = AesKeyWrap.Unwrap(key, kek);

            //then
            Assert.That(test, Is.EqualTo(expected));
        }

        [Test]
        public void Wrap_128Key_192Kek()
        {
            //given (Section 4.2)

            //000102030405060708090A0B0C0D0E0F1011121314151617
            byte[] kek = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23 };

            //00112233445566778899AABBCCDDEEFF
            byte[] key = { 0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255 };

            //96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D
            byte[] expected = { 150, 119, 139, 37, 174, 108, 164, 53, 249, 43, 91, 151, 192, 80, 174, 210, 70, 138, 184, 161, 122, 216, 78, 93 };

            //when
            byte[] test = AesKeyWrap.Wrap(key, kek);

            //then
            Assert.That(test,Is.EqualTo(expected));
        }

        [Test]
        public void Unwrap_128Key_192Kek()
        {
            //given (Section 4.2)

            //000102030405060708090A0B0C0D0E0F1011121314151617
            byte[] kek = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23 };

            //00112233445566778899AABBCCDDEEFF
            byte[] expected = { 0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255 };

            //96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D
            byte[] key = { 150, 119, 139, 37, 174, 108, 164, 53, 249, 43, 91, 151, 192, 80, 174, 210, 70, 138, 184, 161, 122, 216, 78, 93 };

            //when
            byte[] test = AesKeyWrap.Unwrap(key, kek);

            //then
            Assert.That(test,Is.EqualTo(expected));
        }

        [Test]
        public void Wrap_128Key_256Kek()
        {
            //given (Section 4.3)

            //000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
            byte[] kek = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };

            //00112233445566778899AABBCCDDEEFF
            byte[] key = { 0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255 };

            //64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7
            byte[] expected = { 100, 232, 195, 249, 206, 15, 91, 162, 99, 233, 119, 121, 5, 129, 138, 42, 147, 200, 25, 30, 125, 110, 138, 231 };

            //when
            byte[] test = AesKeyWrap.Wrap(key, kek);

            //then
            Assert.That(test,Is.EqualTo(expected));
        }

        [Test]
        public void Unwrap_128Key_256Kek()
        {
            //given (Section 4.3)

            //000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
            byte[] kek = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };

            //00112233445566778899AABBCCDDEEFF
            byte[] expected = { 0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255 };

            //64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7
            byte[] key = { 100, 232, 195, 249, 206, 15, 91, 162, 99, 233, 119, 121, 5, 129, 138, 42, 147, 200, 25, 30, 125, 110, 138, 231 };

            //when
            byte[] test = AesKeyWrap.Unwrap(key, kek);

            //then
            Assert.That(test,Is.EqualTo(expected));
        }

        [Test]
        public void Wrap_192Key_192Kek()
        {
            //given (Section 4.4)

            //000102030405060708090A0B0C0D0E0F1011121314151617
            byte[] kek = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23 };

            //00112233445566778899AABBCCDDEEFF0001020304050607
            byte[] key = { 0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255, 0, 1, 2, 3, 4, 5, 6, 7 };

            //031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2
            byte[] expected = { 3, 29, 51, 38, 78, 21, 211, 50, 104, 242, 78, 194, 96, 116, 62, 220, 225, 198, 199, 221, 238, 114, 90, 147, 107, 168, 20, 145, 92, 103, 98, 210 };

            //when
            byte[] test = AesKeyWrap.Wrap(key, kek);

            //then
            Assert.That(test,Is.EqualTo(expected));
        }

        [Test]
        public void UnWwrap_192Key_192Kek()
        {
            //given (Section 4.4)

            //000102030405060708090A0B0C0D0E0F1011121314151617
            byte[] kek = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23 };

            //00112233445566778899AABBCCDDEEFF0001020304050607
            byte[] expected = { 0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255, 0, 1, 2, 3, 4, 5, 6, 7 };

            //031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2
            byte[] key = { 3, 29, 51, 38, 78, 21, 211, 50, 104, 242, 78, 194, 96, 116, 62, 220, 225, 198, 199, 221, 238, 114, 90, 147, 107, 168, 20, 145, 92, 103, 98, 210 };

            //when
            byte[] test = AesKeyWrap.Unwrap(key, kek);

            //then
            Assert.That(test,Is.EqualTo(expected));
        }

        [Test]
        public void Wrap_192Key_256Kek()
        {
            //given (Section 4.5)

            //000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
            byte[] kek = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };

            //00112233445566778899AABBCCDDEEFF0001020304050607
            byte[] key = { 0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255, 0, 1, 2, 3, 4, 5, 6, 7 };

            //A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1
            byte[] expected = { 168, 249, 188, 22, 18, 198, 139, 63, 246, 230, 244, 251, 227, 14, 113, 228, 118, 156, 139, 128, 163, 44, 184, 149, 140, 213, 209, 125, 107, 37, 77, 161 };

            //when
            byte[] test = AesKeyWrap.Wrap(key, kek);

            //then
            Assert.That(test,Is.EqualTo(expected));
        }

        [Test]
        public void Unwrap_192Key_256Kek()
        {
            //given (Section 4.5)

            //000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
            byte[] kek = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };

            //00112233445566778899AABBCCDDEEFF0001020304050607
            byte[] expected = { 0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255, 0, 1, 2, 3, 4, 5, 6, 7 };

            //A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1
            byte[] key = { 168, 249, 188, 22, 18, 198, 139, 63, 246, 230, 244, 251, 227, 14, 113, 228, 118, 156, 139, 128, 163, 44, 184, 149, 140, 213, 209, 125, 107, 37, 77, 161 };

            //when
            byte[] test = AesKeyWrap.Unwrap(key, kek);

            //then
            Assert.That(test,Is.EqualTo(expected));
        }

        [Test]
        public void Wrap_256Key_256Kek()
        {
            //given (Section 4.6)

            //000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
            byte[] kek = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };

            //00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F
            byte[] key = { 0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

            //28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21
            byte[] expected = { 40, 201, 244, 4, 196, 184, 16, 244, 203, 204, 179, 92, 251, 135, 248, 38, 63, 87, 134, 226, 216, 14, 211, 38, 203, 199, 240, 231, 26, 153, 244, 59, 251, 152, 139, 155, 122, 2, 221, 33 };

            //when
            byte[] test = AesKeyWrap.Wrap(key, kek);

            //then
            Assert.That(test,Is.EqualTo(expected));
        }

        [Test]
        public void Unwrap_256Key_256Kek()
        {
            //given (Section 4.6)

            //000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
            byte[] kek = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };

            //00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F
            byte[] expected = { 0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

            //28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21
            byte[] key = { 40, 201, 244, 4, 196, 184, 16, 244, 203, 204, 179, 92, 251, 135, 248, 38, 63, 87, 134, 226, 216, 14, 211, 38, 203, 199, 240, 231, 26, 153, 244, 59, 251, 152, 139, 155, 122, 2, 221, 33 };

            //when
            byte[] test = AesKeyWrap.Unwrap(key, kek);

            //then
            Assert.That(test,Is.EqualTo(expected));
        }
    }
}