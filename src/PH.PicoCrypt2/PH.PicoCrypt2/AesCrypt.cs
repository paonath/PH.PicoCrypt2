using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using JetBrains.Annotations;

namespace PH.PicoCrypt2
{
    /// <summary>
    /// Crypt Service based on AES Alg.
    /// </summary>
    /// <seealso cref="PH.PicoCrypt2.IPicoCrypt" />
    public class AesCrypt : IPicoCrypt
    {
        private readonly Random _r;
        private SHA256 _sha256;
        private SHA512 _sha512;

        /// <summary>
        /// Initializes a new instance of the <see cref="AesCrypt"/> class.
        /// </summary>
        public AesCrypt()
        {
            _r       = new Random();
            _sha256  = SHA256Managed.Create();
            _sha512  = SHA512Managed.Create();
            Disposed = false;

        }

        /// <summary>
        /// Gets a value indicating whether this <see cref="AesCrypt"/> is disposed.
        /// </summary>
        /// <value><c>true</c> if disposed; otherwise, <c>false</c>.</value>
        public bool Disposed { get; private set; }

        /// <summary>Encrypt a UTF8 text</summary>
        /// <param name="plainText">text to encrypt</param>
        /// <param name="password">cypher password</param>
        /// <returns>encrypted text</returns>
        /// <exception cref="ArgumentException">
        /// Value cannot be null or empty or WhiteSpace. - plainText
        /// or
        /// Value cannot be null or empty or WhiteSpace. - password
        /// </exception>
        [NotNull]
        public string EncryptUtf8([NotNull] string plainText, [NotNull] string password)
        {
            return EncryptUtf8(plainText, password, password);
        }
       


        /// <summary>Encrypt a UTF8 text</summary>
        /// <param name="plainText">text to encrypt</param>
        /// <param name="password">cypher password</param>
        /// <param name="salt">cypher salt</param>
        /// <returns>encrypted text</returns>
        /// <exception cref="ArgumentException">
        /// Value cannot be null or empty or WhiteSpace. - plainText
        /// or
        /// Value cannot be null or empty or WhiteSpace. - password
        /// or
        /// Value cannot be null or empty or WhiteSpace. - salt
        /// </exception>
        [NotNull]
        public string EncryptUtf8([NotNull] string plainText, [NotNull] string password, [NotNull] string salt)
        {
            if (string.IsNullOrEmpty(plainText) ||string.IsNullOrWhiteSpace(plainText))
            {
                throw new ArgumentException("Value cannot be null or empty or WhiteSpace.", nameof(plainText));
            }
            if (string.IsNullOrEmpty(password) ||string.IsNullOrWhiteSpace(password))
            {
                throw new ArgumentException("Value cannot be null or empty or WhiteSpace.", nameof(password));
            }
            if (string.IsNullOrEmpty(salt) ||string.IsNullOrWhiteSpace(salt))
            {
                throw new ArgumentException("Value cannot be null or empty or WhiteSpace.", nameof(salt));
            }

            using (var r = GetCipher(password, salt))
            {
                using (var encryptor = r.CreateEncryptor(r.Key, r.IV))
                {
                    using (var msEncrypt = new MemoryStream())
                    {
                        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            using (var swEncrypt = new StreamWriter(csEncrypt))
                            {
                                // Write all data to the stream.
                                swEncrypt.Write(plainText);
                            }
                        }

                        return Convert.ToBase64String(msEncrypt.ToArray());
                    }
                }    
            }
        }

        /// <summary>Decrpyt a UTF8 text</summary>
        /// <param name="encryptedText">UTF8 text encrypted</param>
        /// <param name="password">cypher password</param>
        /// <param name="throwOnError">if True on error throw exception, otherwise return string null</param>
        /// <returns>plain text or null</returns>
        [CanBeNull]
        public string DecryptUtf8(string encryptedText, string password, bool throwOnError = false)
        {
            return DecryptUtf8(encryptedText, password, password,throwOnError);
        }

        /// <summary>Privates the decrypt UTF8.</summary>
        /// <param name="encryptedText">The encrypted text.</param>
        /// <param name="password">The password.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="throwOnError">if set to <c>true</c> throw exception on error.</param>
        /// <returns></returns>
        [CanBeNull]
        private string PrivateDecryptUtf8(string encryptedText, string password, string salt, bool throwOnError = false)
        {
            try
            {
                
                using (var r = GetCipher(password, salt))
                {
                    var data = Convert.FromBase64String(encryptedText);

                    using (var memoryStream = new MemoryStream(data))
                    {
                        using (var dataOut = new MemoryStream())
                        {
                            using (
                                var cryptoStream = new CryptoStream(
                                                                    memoryStream,
                                                                    r.CreateDecryptor(r.Key, r.IV),
                                                                    CryptoStreamMode.Read))
                            {
                                using (var decryptedData = new BinaryReader(cryptoStream))
                                {
                                    var buffer = new byte[16];
                                    int count;
                                    while ((count = decryptedData.Read(buffer, 0, buffer.Length)) != 0) dataOut.Write(buffer, 0, count);

                                    return System.Text.Encoding.UTF8.GetString(dataOut.ToArray());
                                }
                            }
                        }
                    }
                }

            }
            catch /*(Exception exception)*/
            {
                if (throwOnError)
                {
                    throw;
                }

                return null;

            }
        }

        /// <summary>Decrpyt a UTF8 text</summary>
        /// <param name="encryptedText">UTF8 text encrypted</param>
        /// <param name="password">cypher password</param>
        /// <param name="salt">cypher salt</param>
        /// <param name="throwOnError">if True on error throw exception, otherwise return string null</param>
        /// <returns>plain text or null</returns>
        [CanBeNull]
        public string DecryptUtf8(string encryptedText, string password, string salt, bool throwOnError = false)
        {
            return PrivateDecryptUtf8(encryptedText, password, salt, throwOnError);
        }


        /// <summary>Generate a Random string value</summary>
        /// <param name="length">string length</param>
        /// <param name="mode">random mode</param>
        /// <returns></returns>
        [NotNull]
        public string GenerateRandomString(int length, RandomStringMode mode = RandomStringMode.Full)
        {
            return GenerateRandomString(length, new List<string>(), mode);
        }

        /// <summary>Privates the generate random string.</summary>
        /// <param name="length">The length.</param>
        /// <param name="mode">The mode.</param>
        /// <returns></returns>
        /// <exception cref="ArgumentOutOfRangeException">mode - null</exception>
        [NotNull]
        private string PrivateGenerateRandomString(int length, RandomStringMode mode)
        {
            string charsUP = "QWERTYUIOPASDFGHJKLZXCVBNM";
            string charsLO = "qwertyuiopasdfghjklzxcvbnm";
            string sims    = "|\\!\"£%&/()=?'^[]+*@#°,;.:-_<>";
            string chars   = $@"QqWwEe€RrTtYyUuIiOoPpéè[*++AaSsDdFfGgHhJjKkLlçò@°à#§ù><ZzXxCcVvBbNnMm-_1!23£4$5%6&7890?ì^";
            string numbers = "1234567890";

            switch (mode)
            {
                case RandomStringMode.Full:
                    break;
                case RandomStringMode.CharactersOnly:
                    sims    = charsLO;
                    chars   = $"{charsUP}{charsLO}";
                    numbers = charsUP;
                    break;
                case RandomStringMode.CharacterAndNumbers:
                    sims  = charsLO;
                    chars = $"{charsUP}{charsLO}";
                    break;
                case RandomStringMode.SymbolsAndNumbers:
                    charsUP = sims;
                    charsLO = numbers;
                    chars   = $"{charsUP}{charsLO}";
                    break;
                case RandomStringMode.OnlySymbols:
                    charsUP = sims;
                    charsLO = sims;
                    //sims    = "|\\!\"£%&/()=?'^[]+*@#°,;.:-_<>";
                    chars   = sims;
                    numbers = sims;
                    break;
                case RandomStringMode.OnlyNumbers:
                    charsUP = numbers;
                    charsLO = numbers;
                    sims    = numbers;
                    chars   = numbers;
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(mode), mode, null);
            }
            

            var first = new String(Enumerable.Repeat(charsLO, 1)
                                             .Select(s => s[_r.Next(s.Length)]).ToArray());
            var second = new String(Enumerable.Repeat(charsUP, 1)
                                              .Select(s => s[_r.Next(s.Length)]).ToArray());
            var numberRand = new String(Enumerable.Repeat(numbers, 1)
                                                  .Select(s => s[_r.Next(s.Length)]).ToArray());

            var sim = new String(Enumerable.Repeat(sims, 1)
                                           .Select(s => s[_r.Next(s.Length)]).ToArray());

            var last = "";
            if(length >4)
            {
                last = new string(Enumerable.Repeat(chars, length)
                                            .Select(s => s[_r.Next(s.Length)]).ToArray());
            }

            return $"{first}{numberRand}{sim}{second}{last}".Substring(0,length);
        }

        /// <summary>Generate a Random string value excluding given values</summary>
        /// <param name="length">string length</param>
        /// <param name="excludeValues">string to exclude</param>
        /// <param name="mode">random mode</param>
        /// <returns>a random string</returns>
        [NotNull]
        public string GenerateRandomString(int length, [NotNull] List<string> excludeValues, RandomStringMode mode = RandomStringMode.Full)
        {
            string randomS = PrivateGenerateRandomString(length,mode);
            if (excludeValues.Count == 0)
            {
                return randomS;
            }
            else
            {
                

                while (excludeValues.Contains(randomS)) randomS = PrivateGenerateRandomString(length,mode);

                return randomS;

            }


        }

        /// <summary>Generate a Random string value excluding given regex pattern</summary>
        /// <param name="length">string length</param>
        /// <param name="excludePattern">pattern for exclusion</param>
        /// <param name="mode">random mode</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException">excludePattern</exception>
        [NotNull]
        public string GenerateRandomString(int length, [NotNull] Regex excludePattern, RandomStringMode mode = RandomStringMode.Full)
        {
            if (excludePattern is null)
            {
                throw new ArgumentNullException(nameof(excludePattern));
            }

            string randomS = PrivateGenerateRandomString(length, mode);

            while (excludePattern.IsMatch(randomS)) randomS = PrivateGenerateRandomString(length, mode);

            return randomS;

            
        }

        /// <summary>
        /// Generate a Random string value excluding given values and pattern
        /// </summary>
        /// <param name="length">string length</param>
        /// <param name="excludeValues">string to exclude</param>
        /// <param name="excludePattern">pattern for exclusion</param>
        /// <param name="mode">random mode</param>
        /// <returns>a random string</returns>
        /// <exception cref="ArgumentNullException">excludePattern</exception>
        /// <exception cref="ArgumentException">Value cannot be an empty collection. - excludeValues</exception>
        [NotNull]
        public string GenerateRandomString(int length, [NotNull] List<string> excludeValues, [NotNull] Regex excludePattern, RandomStringMode mode = RandomStringMode.Full)
        {
            if (excludePattern is null)
            {
                throw new ArgumentNullException(nameof(excludePattern));
            }

            if (excludeValues.Count == 0)
            {
                throw new ArgumentException("Value cannot be an empty collection.", nameof(excludeValues));
            }

            string randomS = PrivateGenerateRandomString(length,mode);

            while (excludePattern.IsMatch(randomS) || excludeValues.Contains(randomS)) randomS = PrivateGenerateRandomString(length, mode);

            return randomS;
        }

        /// <summary>Gets the cipher.</summary>
        /// <param name="szKeyBase">The sz key base.</param>
        /// <param name="szIVBase">The sz iv base.</param>
        /// <returns></returns>
        [NotNull]
        private Rijndael GetCipher([NotNull] string szKeyBase, [NotNull] string szIVBase)
        {
            using (SHA256 sha = SHA256Managed.Create())
            {

                var keySha = sha.ComputeHash(Encoding.UTF8.GetBytes(szKeyBase));
                var ivSha  = sha.ComputeHash(Encoding.UTF8.GetBytes(szIVBase));

                Rijndael r = new RijndaelManaged()
                {
                    Mode      = CipherMode.CBC,
                    Padding   = PaddingMode.PKCS7,
                    BlockSize = 128,
                    KeySize   = 256
                };

                r.Key = keySha;                   // 256 bit key size
                r.IV  = ivSha.Take(16).ToArray(); // 128 bit block size

                return r;
            }
        }


        /// <summary>Encode Base 64 string from plain text</summary>
        /// <param name="plainText">text to encode</param>
        /// <returns>base64 encoded string</returns>
        [NotNull]
        public string Base64Encode([NotNull] string plainText)
        {
            return AesCrypt.StringBase64Encode(plainText);
        }

        /// <summary>Strings the base64 encode.</summary>
        /// <param name="plainText">The plain text.</param>
        /// <returns></returns>
        [NotNull]
        public static string StringBase64Encode([NotNull] string plainText)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return System.Convert.ToBase64String(plainTextBytes);
        }

        /// <summary>Strings the base64 decode.</summary>
        /// <param name="base64EncodedData">The base64 encoded data.</param>
        /// <returns></returns>
        [NotNull]
        public static string StringBase64Decode([NotNull] string base64EncodedData)
        {
            var base64EncodedBytes = System.Convert.FromBase64String(base64EncodedData);
            return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
        }

        /// <summary>Decode a Base 64 string</summary>
        /// <param name="base64EncodedData">base64 encoded string</param>
        /// <returns>plain text</returns>
        [NotNull]
        public string Base64Decode([NotNull] string base64EncodedData)
        {
            return AesCrypt.StringBase64Decode(base64EncodedData);
        }




        /// <summary>Gets the string from hash.</summary>
        /// <param name="hash">The hash.</param>
        /// <returns></returns>
        [NotNull]
        private static string GetStringFromHash([NotNull] byte[] hash)
        {
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < hash.Length; i++)
            {
                result.Append(hash[i].ToString("X2"));
            }
            return result.ToString();
        }

        /// <summary>
        /// Computes the hash value for the specified string returning as string
        /// </summary>
        /// <param name="inputValue">string to be hashed</param>
        /// <returns>hash string</returns>
        [NotNull]
        public string GenerateSha256String([NotNull] string inputValue)
        {
            
            byte[] bytes = Encoding.UTF8.GetBytes(inputValue);
            byte[] hash  = _sha256.ComputeHash(bytes);
            return GetStringFromHash(hash);
        }

        /// <summary>
        /// Computes the hash value for the specified string returning as string
        /// </summary>
        /// <param name="inputValue">string to be hashed</param>
        /// <returns>hash string</returns>
        [NotNull]
        public string GenerateSha512String([NotNull] string inputValue)
        {
            
            byte[] bytes = Encoding.UTF8.GetBytes(inputValue);
            byte[] hash  = _sha512.ComputeHash(bytes);
            return GetStringFromHash(hash);
        }

        /// <summary>Releases unmanaged and - optionally - managed resources.</summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (disposing && !Disposed)
            {
                Disposed = true;
                _sha256?.Dispose();
                _sha512?.Dispose();
            }
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}