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
    }
}