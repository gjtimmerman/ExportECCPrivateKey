using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace ExportECCPrivateKey
{
    internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length != 2) {
                Console.WriteLine("Usage: ExportECCPrivateKey SubjectName Password");
                return;
            }
            X509Store myStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            myStore.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection myCollection = myStore.Certificates.Find(X509FindType.FindBySubjectName, args[0], false);
            ECDsa ?myPrivateKey = myCollection[0].GetECDsaPrivateKey();
            if (myPrivateKey == null)
            {
                Console.WriteLine("Key niet kunnen ophalen");

            }
            else
            {
                PbeParameters pbeParameters = new PbeParameters(PbeEncryptionAlgorithm.Aes128Cbc,HashAlgorithmName.SHA256, 1000);
                byte[] myPrivateKeyBytes = myPrivateKey.ExportEncryptedPkcs8PrivateKey(args[1],pbeParameters);
                FileStream fileStream = new FileStream(args[0] + ".key", FileMode.Create);
                fileStream.Write(myPrivateKeyBytes, 0, myPrivateKeyBytes.Length);
                fileStream.Close();
                ECDsa importedPrivateKey = ECDsa.Create();
                importedPrivateKey.ImportEncryptedPkcs8PrivateKey(args[1], myPrivateKeyBytes, out int bytesRead);
                ECParameters myECParameters = importedPrivateKey.ExportParameters(true);
                Console.WriteLine("Private Key:");
                for (int i = 0; i < myECParameters.D.Length; i++)
                {
                    Console.Write($"{myECParameters.D[i]:X2}");
                }
                Console.WriteLine();
                Console.WriteLine();

                Console.WriteLine("Public Key:");
                Console.WriteLine("X:");
                for (int i = 0; i < myECParameters.Q.X.Length; i++)
                {
                    Console.Write($"{myECParameters.Q.X[i]:X2}");
                }
                Console.WriteLine();
                Console.WriteLine("Y:");
                for (int i = 0; i < myECParameters.Q.Y.Length; i++)
                {
                    Console.Write($"{myECParameters.Q.Y[i]:X2}");
                }
                Console.WriteLine();
            }
        }
    }
}