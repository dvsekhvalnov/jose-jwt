using System;
using System.Security.Cryptography;
using Jose;
using NUnit.Framework;
using Security.Cryptography;

namespace UnitTests
{
    /// <summary>
    /// Contains tests for potential security vulnerabilities/attacks found by security researchers in different JWT/JOSE
    /// implementations.
    /// 
    /// Idea is to track all found security issues and have bullet proof tests against them to mitigate ongoing security
    /// risks for library.
    /// </summary>
    [TestFixture]
    public class SecurityVulnerabilitiesTest
    {
        [Test]
        public void InvalidCurveAttack()
        {
            // https://www.cs.bris.ac.uk/Research/CryptographySecurity/RWC/2017/nguyen.quan.pdf
            // Attack exploits some ECDH implementations which do not check 
            // that ephemeral public key is on the private key's curve.

            byte[] x = Base64Url.Decode("weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ");
            byte[] y = Base64Url.Decode("e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck");
            byte[] d = Base64Url.Decode("VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw");

            var privateKey = EccKey.New(x, y, d, usage: CngKeyUsages.KeyAgreement);

            //JWT encrypted with attacker private key, which is equals to (reciever_pk mod 113)
            var attackMod113 =
                "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiZ1RsaTY1ZVRRN3otQmgxNDdmZjhLM203azJVaURpRzJMcFlrV0FhRkpDYyIsInkiOiJjTEFuakthNGJ6akQ3REpWUHdhOUVQclJ6TUc3ck9OZ3NpVUQta2YzMEZzIiwiY3J2IjoiUC0yNTYifX0.qGAdxtEnrV_3zbIxU2ZKrMWcejNltjA_dtefBFnRh9A2z9cNIqYRWg.pEA5kX304PMCOmFSKX_cEg.a9fwUrx2JXi1OnWEMOmZhXd94-bEGCH9xxRwqcGuG2AMo-AwHoljdsH5C_kcTqlXS5p51OB1tvgQcMwB5rpTxg.72CHiYFecyDvuUa43KKT6w";

            //JWT encrypted with attacker private key, which is equals to (reciever_pk mod 2447)
            var attackMod2447 =
                "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiWE9YR1E5XzZRQ3ZCZzN1OHZDSS1VZEJ2SUNBRWNOTkJyZnFkN3RHN29RNCIsInkiOiJoUW9XTm90bk56S2x3aUNuZUprTElxRG5UTnc3SXNkQkM1M1ZVcVZqVkpjIiwiY3J2IjoiUC0yNTYifX0.UGb3hX3ePAvtFB9TCdWsNkFTv9QWxSr3MpYNiSBdW630uRXRBT3sxw.6VpU84oMob16DxOR98YTRw.y1UslvtkoWdl9HpugfP0rSAkTw1xhm_LbK1iRXzGdpYqNwIG5VU33UBpKAtKFBoA1Kk_sYtfnHYAvn-aes4FTg.UZPN8h7FcvA5MIOq-Pkj8A";

            try
            {
                JWT.Decode(attackMod113, privateKey);
                Assert.True(false, "Should fail with CrytographicException");
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e);
            }

            try
            {
                JWT.Decode(attackMod2447, privateKey);
                Assert.True(false, "Should fail with CrytographicException");
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e);
            }
        }

        [Test]
        [ExpectedException(typeof(Jose.IntegrityException))]
        public void BitLengthIntegerOverflow()
        {
            //Borrowed test case from https://bitbucket.org/b_c/jose4j/commits/b79e67c13c23

            byte[] cek =
            {
                57, 188, 52, 101, 199, 208, 135, 76, 159, 67, 65, 71, 196, 136, 137, 113, 227, 232, 28, 1, 61,
                157, 73, 156, 68, 103, 67, 250, 215, 162, 181, 161
            };

            AesCbcHmacEncryption enc = new AesCbcHmacEncryption(new HmacUsingSha("SHA256"), 256);

            byte[] aad = new byte[8];
            byte[] plaintext = new byte[536870928];

            //random plaintext
            for (int i = 0; i < plaintext.Length; i = i + 8)
            {                
                byte[] bytes = Arrays.IntToBytes(i);
                plaintext[i] = bytes[0];
                plaintext[i + 1] = bytes[1];
                plaintext[i + 2] = bytes[2];
                plaintext[i + 3] = bytes[3];
            }

            var parts = enc.Encrypt(aad, plaintext, cek);

            byte[] iv = parts[0];
            byte[] ciphertext = parts[1];
            byte[] authTag = parts[2];

            // Now shift aad and ciphertext around so that HMAC doesn't change,
            // but the plaintext will change.
            byte[] buffer = Arrays.Concat(aad, iv, ciphertext);

            int newAadSize = 536870920; // Note that due to integer overflow 536870920 * 8 = 64

            byte[] newAad = new byte[newAadSize];
            Buffer.BlockCopy(buffer, 0, newAad, 0, newAadSize);

            byte[] newIv = new byte[16];
            Buffer.BlockCopy(buffer, newAadSize, newIv, 0, 16);

            byte[] newCiphertext = new byte[buffer.Length - newAadSize - 16];
            Buffer.BlockCopy(buffer, newAadSize + 16, newCiphertext, 0, buffer.Length - newAadSize - 16);

            //decrypt shifted binary, it should fail, since content is different now
            var test = enc.Decrypt(newAad, cek, newIv, newCiphertext, authTag);

            //if we reach that point HMAC check was bypassed although the decrypted data is different
            Assert.Fail("JoseException should be raised.");
        }
    }
}