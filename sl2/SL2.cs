using System.Security.Cryptography;
using System.Text;

namespace sl2lib
{
    /// <summary>
    /// A simple class for decrypting and encrypting SL2 files.
    /// </summary>
    public static class SL2
    {
        private const int _ivSize = 0x10;
        private const int _checksumStartOffset = 4;
        private const int _paddingLength = 0xC;

        /// <summary>
        /// Decrypts a file from an SL2.
        /// </summary>
        public static byte[] Decrypt(byte[] bytes, byte[] key, out byte[] iv)
        {
            iv = new byte[_ivSize];
            Buffer.BlockCopy(bytes, 0, iv, 0, _ivSize);

            using Aes aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.BlockSize = 128;

            // PKCS7-style padding is used, but they don't include the minimum padding
            // so it can't be stripped safely
            aes.Padding = PaddingMode.None;
            aes.Key = key;
            aes.IV = iv;

            ICryptoTransform decryptor = aes.CreateDecryptor();
            using MemoryStream encStream = new(bytes, _ivSize, bytes.Length - _ivSize);
            using CryptoStream cryptoStream = new(encStream, decryptor, CryptoStreamMode.Read);
            using MemoryStream decStream = new();
            cryptoStream.CopyTo(decStream);
            return decStream.ToArray();
        }

        /// <summary>
        /// Encrypts a file for an SL2.
        /// </summary>
        public static byte[] Encrypt(byte[] bytes, byte[] key, byte[] iv)
        {
            using Aes aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.BlockSize = 128;
            aes.Padding = PaddingMode.None;
            aes.Key = key;
            aes.IV = iv;

            ICryptoTransform encryptor = aes.CreateEncryptor();
            using var decStream = new MemoryStream(bytes);
            using var cryptoStream = new CryptoStream(decStream, encryptor, CryptoStreamMode.Read);
            using var encStream = new MemoryStream();
            encStream.Write(aes.IV, 0, _ivSize);
            cryptoStream.CopyTo(encStream);
            return encStream.ToArray();
        }

        /// <summary>
        /// Calculates the checksum of a file in an SL2.
        /// </summary>
        /// <param name="bytes">The decrypted bytes of a file in an SL2.</param>
        /// <returns>The calcylated checksum.</returns>
        public static byte[] CalculateChecksum(byte[] bytes)
        {
            int checksummedBytesEnd = bytes.Length - (MD5.HashSizeInBytes + _paddingLength);
            byte[] bytesToHash = bytes[_checksumStartOffset..checksummedBytesEnd];
            return MD5.HashData(bytesToHash);
        }

        /// <summary>
        /// Updates the checksum of a file in an SL2.
        /// </summary>
        /// <param name="bytes">The decrypted bytes of an SL2.</param>
        public static void UpdateChecksum(byte[] bytes)
        {
            byte[] checksum = CalculateChecksum(bytes);
            int hashedBytesEnd = bytes.Length - (MD5.HashSizeInBytes + _paddingLength);
            Array.Copy(checksum, 0, bytes, hashedBytesEnd, checksum.Length);
        }
    }
}