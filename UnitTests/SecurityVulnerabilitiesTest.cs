using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Jose;
using Jose.keys;
using Xunit;
using Xunit.Abstractions;

namespace UnitTests
{
    /// <summary>
    /// <para>
    /// Contains tests for potential security vulnerabilities/attacks found by security researchers in different JWT/JOSE
    /// implementations.
    /// </para>
    /// <para>
    /// Idea is to track all found security issues and have bullet proof tests against them to mitigate ongoing security
    /// risks for library.
    /// </para>
    /// </summary>
    public class SecurityVulnerabilitiesTest
    {
        private readonly TestConsole Console;

        private static readonly byte[] aes128Key = new byte[] { 194, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133 };

        public SecurityVulnerabilitiesTest(ITestOutputHelper output)
        {
            this.Console = new TestConsole(output);
        }

        [Fact]
        public void UnboundedPBKDF2Attack()
        {
            try
            {
                //forged token with 10mlns hash iterations
                string token = "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJpdiI6Inh1MWlHLXpMVERWaWU3b3YiLCJ0YWciOiJacExHZWVtaElFeUZDdS1iUk9jZlhnIiwiZW5jIjoiQTEyOEdDTSIsInAyYyI6MTAwMDAwMDAsInAycyI6Ik5rWGppMTk0N2ZSc0tUbEIifQ.-E0s5d6yAV0jRoT21YKURA.NOzw8pTGuxfe8kvC.NZAFt1_Kv1hglGgbGg.ev7SjmNduQgEWvPGh9SUmg";
                var payload = Jose.JWT.Decode(token, "whatever");
                Assert.True(false, "Should fail with ArgumentException");
            }
            catch (ArgumentException e)
            {
                Console.Out.WriteLine(e.ToString());
            }
        }

        [SkippableTheory]
        [InlineData("CNG")]
        [InlineData("ECDH")]
        public void InvalidCurveAttack(string keyImplementation)
        {
            if (keyImplementation == "CNG")
            {
                Skip.IfNot(RuntimeInformation.IsOSPlatform(OSPlatform.Windows), "CNG is Windows only");
            }

            // https://www.cs.bris.ac.uk/Research/CryptographySecurity/RWC/2017/nguyen.quan.pdf
            // Attack exploits some ECDH implementations which do not check
            // that ephemeral public key is on the private key's curve.

            byte[] x = Base64Url.Decode("weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ");
            byte[] y = Base64Url.Decode("e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck");
            byte[] d = Base64Url.Decode("VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw");

            var privateKey = keyImplementation == "CNG" ? (object)EccKey.New(x, y, d, usage: CngKeyUsages.KeyAgreement) : EcdhKey.New(x, y, d);

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
            catch (PlatformNotSupportedException e)
            {
                Console.Out.WriteLine(e.ToString());
            }
            catch (CryptographicException e)
            {
                Console.Out.WriteLine(e.ToString());
            }
            catch (IntegrityException e)
            {
                Console.Out.WriteLine(e.ToString());
            }

            try
            {
                JWT.Decode(attackMod2447, privateKey);
                Assert.True(false, "Should fail with CrytographicException");
            }
            catch (PlatformNotSupportedException e)
            {
                Console.Out.WriteLine(e.ToString());
            }
            catch (CryptographicException e)
            {
                Console.Out.WriteLine(e.ToString());
            }
            catch (IntegrityException e)
            {
                Console.Out.WriteLine(e.ToString());
            }
        }

        [Fact]
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

            try
            {
                //decrypt shifted binary, it should fail, since content is different now
                var test = enc.Decrypt(newAad, cek, newIv, newCiphertext, authTag);

                //if we reach that point HMAC check was bypassed although the decrypted data is different
                Assert.True(false, "JoseException should be raised.");
            }
            catch (Jose.IntegrityException e)
            {
                Console.Out.WriteLine(e.ToString());
            }
        }

        [Fact]
        public void DeflateBomb()
        {
            // given
            Jwk privateKey = new Jwk(
                e: "AQAB",
                n: "qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q",
                p: "0qaOkT174vRG3E_67gU3lgOgoT6L3pVHuu7wfrIEoxycPa5_mZVG54SgvQUofGUYEGjR0lavUAjClw9tOzcODHX8RAxkuDntAFntBxgRM-IzAy8QzeRl_cbhgVjBTAhBcxg-3VySv5GdxFyrQaIo8Oy_PPI1L4EFKZHmicBd3ts",
                q: "zJPqCDKqaJH9TAGfzt6b4aNt9fpirEcdpAF1bCedFfQmUZM0LG3rMtOAIhjEXgADt5GB8ZNK3BQl8BJyMmKs57oKmbVcODERCtPqjECXXsxH-az9nzxatPvcb7imFW8OlWslwr4IIRKdEjzEYs4syQJz7k2ktqOpYI5_UfYnw1s",
                d: "lJhwb0pKlB2ivyDFO6thajotClrMA3nxIiSkIUbvVr-TToFtha36gyF6w6e6YNXQXs4HhMRy1_b-nRQDk8G4_f5urd_q-pOn5u4KfmqN3Xw-lYD3ddi9qF0NLeTVUNVFASeP0FFqbPYfdNwD-LyvwjhtT_ggMOAw3mYvU5cBfz6-3uPdhl3CwQFCTgwOud_BA9p2MPMUHG82wMK_sNO1I0TYpjm7TnwNBwiKbMf-i5CKnuohgoYrEDYLeMg3f32eBljlCFNYaoCtT-mr1Ze0OTJND04vbfLotV-BBKulIpbOOSeVpKG7gJxZHmv7in7PE5_WzaxKFVoHW3wR6v_GzQ",
                dp: "KTWmTGmf092AA1euOmRQ5IsfIIxQ5qGDn-FgsRh4acSOGE8L7WrTrTU4EOJyciuA0qz-50xIDbs4_j5pWx1BJVTrnhBin9vNLrVo9mtR6jmFS0ko226kOUpwEVLgtdQjobWLjtiuaMW-_Iw4gKWNptxZ6T1lBD8UWHaPiEFW2-M",
                dq: "Jn0lqMkvemENEMG1eUw0c601wPOMoPD4SKTlnKWPTlQS6YISbNF5UKSuFLwoJa9HA8BifDrD-Mfpo1M1HPmnoilEWUrfwMqqdCkOlbiJQhKY8AZ16QGH50kDXhmVVa8BRWdVQWBTUzWXS5kXMaeskVzextTgymPcOAhXN-ph7MU",
                qi: "sRAPigJpl8S_vsf1zhJTrHM97xRwuB26R6Tm-J8sKRPb7p5xxNlmOBBFvWmWxdto8dBElNlydSZan373yBLxzW-bZgVp-B2RKT1B3WhTYW_Vo5DLhWi84XMncJxH7avtxtF9yksaeKe0e2n3J6TTan53mDg4KF8U0OEO2ciqO9g"
            );

            Jwk publicKey = new Jwk(
                e: "AQAB",
                n: "qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q"
            );

            string strU = new string('U', 400000000);
            string strUU = new string('U', 100000000);
            string payload = $@"{{""U"":""{strU}"", ""UU"":""{strUU}""}}";
            string bomb = Jose.JWT.Encode(payload, publicKey, JweAlgorithm.RSA_OAEP, JweEncryption.A256GCM, JweCompression.DEF);

            // when
            Exception thrownException = Assert.Throws<CapacityExceededException>(() => Jose.JWT.Decode(bomb, privateKey));
        }

        [Fact]
        public void TruncatedGcmAuthTag()
        {
            // given 
            string token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..PEXf1goWOF0SZRe_.Zp3CHYq4ZqM3_opMIy25O50gmQzw_p-nCOiW2ROuQSv80-aD-78n8m103kgPRPCsOt7qrckDRGSDACOBZGr2WovzSC-dxIcW3EsPqtibueyh0p3FY43h-bcbhPzXBdjQPaNTCY0o26wcEV_4FzPYdE9_ngRFIUe_7Kby-E2CWYLFc5D9RO9TLGN5dpHL6l4SOGbNz8M0o4aQuyJv3BV1wj_KswqyVcKBHjm0eh6RmFhoERxWjvt5yeo83bzxTfReVWAxXw.AVLr7JE1r1uiUSLj";

            try
            {
                // when decrypt token with trunated AES GCM tag, it should fail
                Jose.JWT.Decode(token, aes128Key);
                Assert.True(false, "Should fail with IntegrityException");

            }
            catch (ArgumentException e)
            {
                Console.Out.WriteLine(e.ToString());
            }
        }
    }
}