using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Jose.keys;

namespace UnitTests
{
    public interface ITestSuiteUtils
    {
        RSA PrivKey();
        RSA PubKey();
        X509Certificate2 X509();
        object ECDSa256Public();
        object ECDSa256Private();
        object Ecc256Public(CngKeyUsages usage = CngKeyUsages.Signing);
        object Ecc256PublicSigning();
        object Ecc384Public();
        object Ecc384PublicSigning();
        object Ecc384Private();
        object Ecc256Private(CngKeyUsages usage = CngKeyUsages.Signing);
        object Ecc256PrivateSigning();
        object Ecc512Public();
        object Ecc512PublicSigning();
        object Ecc512Private();
    }

    public class TestSuiteEcdhUtils : ITestSuiteUtils
    {
        public TestSuiteEcdhUtils()
        {
        }

        public RSA PrivKey()
        {
            return (RSA)RSACertificateExtensions.GetRSAPrivateKey(X509());
        }

        public RSA PubKey()
        {
            return (RSA)RSACertificateExtensions.GetRSAPublicKey(X509());
        }

        public X509Certificate2 X509()
        {
            return new X509Certificate2("jwt-2048.p12", "1");
        }

        public object Ecc256Public(CngKeyUsages usage = CngKeyUsages.Signing)
        {
            byte[] x = { 4, 114, 29, 223, 58, 3, 191, 170, 67, 128, 229, 33, 242, 178, 157, 150, 133, 25, 209, 139, 166, 69, 55, 26, 84, 48, 169, 165, 67, 232, 98, 9 };
            byte[] y = { 131, 116, 8, 14, 22, 150, 18, 75, 24, 181, 159, 78, 90, 51, 71, 159, 214, 186, 250, 47, 207, 246, 142, 127, 54, 183, 72, 72, 253, 21, 88, 53 };
            byte[] d = { 42, 148, 231, 48, 225, 196, 166, 201, 23, 190, 229, 199, 20, 39, 226, 70, 209, 148, 29, 70, 125, 14, 174, 66, 9, 198, 80, 251, 95, 107, 98, 206 };

            return EcdhKey.New(x, y, usage: usage);
        }

        public object Ecc384Public()
        {
            byte[] x = { 70, 151, 220, 179, 62, 0, 79, 232, 114, 64, 58, 75, 91, 209, 232, 128, 7, 137, 151, 42, 13, 148, 15, 133, 93, 215, 7, 3, 136, 124, 14, 101, 242, 207, 192, 69, 212, 145, 88, 59, 222, 33, 127, 46, 30, 218, 175, 79 };
            byte[] y = { 189, 202, 196, 30, 153, 53, 22, 122, 171, 4, 188, 42, 71, 2, 9, 193, 191, 17, 111, 180, 78, 6, 110, 153, 240, 147, 203, 45, 152, 236, 181, 156, 232, 223, 227, 148, 68, 148, 221, 176, 57, 149, 44, 203, 83, 85, 75, 55 };

            return EcdhKey.New(x, y);
        }

        public object Ecc256Private(CngKeyUsages usage = CngKeyUsages.Signing)
        {
            byte[] x = { 4, 114, 29, 223, 58, 3, 191, 170, 67, 128, 229, 33, 242, 178, 157, 150, 133, 25, 209, 139, 166, 69, 55, 26, 84, 48, 169, 165, 67, 232, 98, 9 };
            byte[] y = { 131, 116, 8, 14, 22, 150, 18, 75, 24, 181, 159, 78, 90, 51, 71, 159, 214, 186, 250, 47, 207, 246, 142, 127, 54, 183, 72, 72, 253, 21, 88, 53 };
            byte[] d = { 42, 148, 231, 48, 225, 196, 166, 201, 23, 190, 229, 199, 20, 39, 226, 70, 209, 148, 29, 70, 125, 14, 174, 66, 9, 198, 80, 251, 95, 107, 98, 206 };

            return EcdhKey.New(x, y, d, usage);
        }

        public object Ecc512Public()
        {
            byte[] x = { 0, 248, 73, 203, 53, 184, 34, 69, 111, 217, 230, 255, 108, 212, 241, 229, 95, 239, 93, 131, 100, 37, 86, 152, 87, 98, 170, 43, 25, 35, 80, 137, 62, 112, 197, 113, 138, 116, 114, 55, 165, 128, 8, 139, 148, 237, 109, 121, 40, 205, 3, 61, 127, 28, 195, 58, 43, 228, 224, 228, 82, 224, 219, 148, 204, 96 };
            byte[] y = { 0, 60, 71, 97, 112, 106, 35, 121, 80, 182, 20, 167, 143, 8, 246, 108, 234, 160, 193, 10, 3, 148, 45, 11, 58, 177, 190, 172, 26, 178, 188, 240, 91, 25, 67, 79, 64, 241, 203, 65, 223, 218, 12, 227, 82, 178, 66, 160, 19, 194, 217, 172, 61, 250, 23, 78, 218, 130, 160, 105, 216, 208, 235, 124, 46, 32 };

            return EcdhKey.New(x, y);
        }

        public object ECDSa256Public()
        {
            var x095 = new X509Certificate2("ecc256.p12", "12345");

            return x095.GetECDsaPublicKey();
        }

	public object Ecc256PublicSigning() 
	{
	   return ECDSa256Public();
	}
	
        public object ECDSa256Private()
        {
            var x095 = new X509Certificate2("ecc256.p12", "12345");

            return x095.GetECDsaPrivateKey();
        }

	public object Ecc256PrivateSigning()
	{
	    return ECDSa256Private();
	}

        public object Ecc384PublicSigning()
        {
            var x095 = new X509Certificate2("ecc384.p12", "12345");

            return x095.GetECDsaPublicKey();
        }

	public object Ecc384Private() 
	{
            var x095 = new X509Certificate2("ecc384.p12", "12345");

            return x095.GetECDsaPrivateKey();
	}

        public object Ecc512PublicSigning()
        {
            #if NET5_0_OR_GREATER
                var x095 = new X509Certificate2("ecc521n.p12", "12345");
            #else
                var x095 = new X509Certificate2("ecc521.p12", "12345");
            #endif

            return x095.GetECDsaPublicKey();
        }

	public object Ecc512Private() 
	{
            #if NET5_0_OR_GREATER
                var x095 = new X509Certificate2("ecc521n.p12", "12345");
            #else
                var x095 = new X509Certificate2("ecc521.p12", "12345");
            #endif

            return x095.GetECDsaPrivateKey();
	}
    }
}