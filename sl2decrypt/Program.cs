using sl2lib;

namespace sl2decrypt
{
    internal class Program
    {
        static readonly byte[] AC6SL2Key = [0xB1, 0x56, 0x87, 0x9F, 0x13, 0x48, 0x97, 0x98, 0x70, 0x05, 0xC4, 0x87, 0x00, 0xAE, 0xF8, 0x79];

        static void Main(string[] args)
        {
            foreach (string arg in args)
            {
                if (File.Exists(arg))
                {
                    byte[] bytes = File.ReadAllBytes(arg);
                    byte[] decryptedBytes = SL2.Decrypt(bytes, AC6SL2Key, out _);
                    File.WriteAllBytes(arg + ".dec", decryptedBytes);
                }
            }
        }
    }
}
