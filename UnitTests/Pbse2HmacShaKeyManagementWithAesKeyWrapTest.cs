using Jose;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;

namespace UnitTests
{
    public class Pbse2HmacShaKeyManagementWithAesKeyWrapTest
    {
        private readonly TestConsole Console;
        //private static readonly byte[] aes128Key = new byte[] { 194, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133 };
        private static readonly byte[] aes256Key  = new byte[] { 164, 60, 194, 0, 161, 189, 41, 38, 130, 89, 141, 164, 45, 170, 159, 209, 69, 137, 243, 216, 191, 131, 47, 250, 32, 107, 231, 117, 37, 158, 225, 234 };

        public Pbse2HmacShaKeyManagementWithAesKeyWrapTest(ITestOutputHelper output)
        {
            Console = new TestConsole(output);
        }

        [Fact]
        public void WrapKeyMinIterations()
        {
            // given
            Pbse2HmacShaKeyManagementWithAesKeyWrap alg = new Pbse2HmacShaKeyManagementWithAesKeyWrap(128, new AesKeyWrapManagement(128), minIterations: 320000);
            var headers = new Dictionary<string, object>();
            headers["p2c"] = 319999;
            headers["alg"] = "PBES2-HS256+A128KW";
            
            try
            {
                alg.WrapNewKey(256, "secret", headers);
                Assert.True(false, "Should fail with ArgumentException");
            }
            catch(ArgumentException e)
            {
                // then
                Console.Out.WriteLine(e.ToString());
            }            
        }

        [Fact]
        public void WrapKeyMinIterationsDefaults()
        {
            // given
            Pbse2HmacShaKeyManagementWithAesKeyWrap alg = new Pbse2HmacShaKeyManagementWithAesKeyWrap(128, new AesKeyWrapManagement(128), minIterations: 320000);
            var headers = new Dictionary<string, object>();
            headers["alg"] = "PBES2-HS256+A128KW";

            // when
            try
            {
                alg.WrapNewKey(256, "secret", headers);
                Assert.True(false, "Should fail with ArgumentException");
            }
            catch(ArgumentException e)
            {
                // then
                Console.Out.WriteLine(e.ToString());
            }            
        }

        [Fact]
        public void WrapKeyMaxIterations()
        {
            // given
            Pbse2HmacShaKeyManagementWithAesKeyWrap alg = new Pbse2HmacShaKeyManagementWithAesKeyWrap(128, new AesKeyWrapManagement(128), maxIterations: 320000);
            var headers = new Dictionary<string, object>();
            headers["p2c"] = 320001;
            headers["alg"] = "PBES2-HS256+A128KW";

            // when
            try
            {
                alg.WrapNewKey(256, "secret", headers);
                Assert.True(false, "Should fail with ArgumentException");
            }
            catch (ArgumentException e)
            {
                // then
                Console.Out.WriteLine(e.ToString());
            }
        }

        [Fact]
        public void UnwrapKeyMinIterations()
        {
            // given            
            Pbse2HmacShaKeyManagementWithAesKeyWrap alg = new Pbse2HmacShaKeyManagementWithAesKeyWrap(128, new AesKeyWrapManagement(128), minIterations: 320000);
            var headers = new Dictionary<string, object>();
            headers["p2c"] = 319999;
            headers["p2s"] = "b0YEVlLzkZ5oTR0L";
            headers["alg"] = "PBES2-HS256+A128KW";

            try
            {
                alg.Unwrap(aes256Key, "secret", 256, headers);
                Assert.True(false, "Should fail with ArgumentException");
            }
            catch (ArgumentException e)
            {
                // then
                Console.Out.WriteLine(e.ToString());
            }
        }

        [Fact]
        public void UnwrapKeyMaxIterations()
        {
            // given            
            Pbse2HmacShaKeyManagementWithAesKeyWrap alg = new Pbse2HmacShaKeyManagementWithAesKeyWrap(128, new AesKeyWrapManagement(128), maxIterations: 320000);
            var headers = new Dictionary<string, object>();
            headers["p2c"] = 320001;
            headers["p2s"] = "b0YEVlLzkZ5oTR0L";
            headers["alg"] = "PBES2-HS256+A128KW";

            try
            {
                alg.Unwrap(aes256Key, "secret", 256, headers);
                Assert.True(false, "Should fail with ArgumentException");
            }
            catch (ArgumentException e)
            {
                // then
                Console.Out.WriteLine(e.ToString());
            }
        }
    }
}
