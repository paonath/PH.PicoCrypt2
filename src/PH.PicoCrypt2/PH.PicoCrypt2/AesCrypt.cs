using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace PH.PicoCrypt2
{
    public class AesCrypt : IPicoCrypt
    {
        readonly Random _r;
        private SHA256 _sha256;
        private SHA512 _sha512;

        public AesCrypt()
        {
            _r       = new Random();
            _sha256  = SHA256Managed.Create();
            _sha512  = SHA512Managed.Create();
            Disposed = false;

        }

        public bool Disposed { get; private set; }

        public string EncryptUtf8(string plainText, string password)
        {
            return EncryptUtf8(plainText, password, password);
        }

        public string EncryptUtf8(string plainText, string password, string salt)
        {
            
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


        public string DecryptUtf8(string encryptedText, string password, bool throwOnError = false)
        {
            return DecryptUtf8(encryptedText, password, password,throwOnError);
        }

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
                                    while ((count = decryptedData.Read(buffer, 0, buffer.Length)) != 0)
                                    {
                                        dataOut.Write(buffer, 0, count);
                                    }

                                    return System.Text.Encoding.UTF8.GetString(dataOut.ToArray());
                                }
                            }
                        }
                    }
                }

            }
            catch(Exception exception)
            {
                if (throwOnError)
                    throw;

                return null;

            }
        }

        public string DecryptUtf8(string encryptedText, string password, string salt, bool throwOnError = false)
        {
            return PrivateDecryptUtf8(encryptedText, password, salt, throwOnError);
        }

        

        public string GenerateRandomString(int length, RandomStringMode mode = RandomStringMode.Full)
        {
            return GenerateRandomString(length, new List<string>(), mode);
        }

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
                last = new string(Enumerable.Repeat(chars, length)
                                            .Select(s => s[_r.Next(s.Length)]).ToArray());

            return $"{first}{numberRand}{sim}{second}{last}".Substring(0,length);
        }

        public string GenerateRandomString(int length, List<string> excludeValues, RandomStringMode mode = RandomStringMode.Full)
        {
            string randomS = PrivateGenerateRandomString(length,mode);
            if (excludeValues.Count == 0)
            {
                return randomS;
            }
            else
            {
                

                while (excludeValues.Contains(randomS))
                {
                    randomS = PrivateGenerateRandomString(length,mode);
                }

                return randomS;

            }


        }

        public string GenerateRandomString(int length, Regex excludePattern, RandomStringMode mode = RandomStringMode.Full)
        {
            if (excludePattern is null) throw new ArgumentNullException(nameof(excludePattern));

            string randomS = PrivateGenerateRandomString(length, mode);

            while (excludePattern.IsMatch(randomS))
            {
                randomS = PrivateGenerateRandomString(length, mode);
            }

            return randomS;

            
        }

        public string GenerateRandomString(int length, List<string> excludeValues, Regex excludePattern, RandomStringMode mode = RandomStringMode.Full)
        {
            if (excludePattern is null) throw new ArgumentNullException(nameof(excludePattern));
            if (excludeValues.Count == 0)
                throw new ArgumentException("Value cannot be an empty collection.", nameof(excludeValues));

            string randomS = PrivateGenerateRandomString(length,mode);

            while (excludePattern.IsMatch(randomS) || excludeValues.Contains(randomS))
            {
                randomS = PrivateGenerateRandomString(length, mode);
            }

            return randomS;
        }

        private Rijndael GetCipher(string szKeyBase, string szIVBase)
        {
            var sha = SHA256Managed.Create();

            var keySHA = sha.ComputeHash(Encoding.UTF8.GetBytes(szKeyBase));
            var ivSHA  = sha.ComputeHash(Encoding.UTF8.GetBytes(szIVBase));

            Rijndael r = new RijndaelManaged()
            {
                Mode      = CipherMode.CBC,
                Padding   = PaddingMode.PKCS7,
                BlockSize = 128,
                KeySize   = 256
            };

            r.Key = keySHA;                   // 256 bit key size
            r.IV  = ivSHA.Take(16).ToArray(); // 128 bit block size

            return r;
        }



        public string Base64Encode(string plainText)
        {
            return AesCrypt.StringBase64Encode(plainText);
        }
        public static string StringBase64Encode(string plainText)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return System.Convert.ToBase64String(plainTextBytes);
        }

        public static string StringBase64Decode(string base64EncodedData)
        {
            var base64EncodedBytes = System.Convert.FromBase64String(base64EncodedData);
            return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
        }

        public string Base64Decode(string base64EncodedData)
        {
            return AesCrypt.StringBase64Decode(base64EncodedData);
        }

        

       

        private static string GetStringFromHash(byte[] hash)
        {
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < hash.Length; i++)
            {
                result.Append(hash[i].ToString("X2"));
            }
            return result.ToString();
        }

        public string GenerateSha256String(string inputValue)
        {
            
            byte[] bytes = Encoding.UTF8.GetBytes(inputValue);
            byte[] hash  = _sha256.ComputeHash(bytes);
            return GetStringFromHash(hash);
        }

        public string GenerateSha512String(string inputValue)
        {
            
            byte[] bytes = Encoding.UTF8.GetBytes(inputValue);
            byte[] hash  = _sha512.ComputeHash(bytes);
            return GetStringFromHash(hash);
        }

        public virtual void Dispose(bool disposing)
        {
            if (disposing && !Disposed)
            {
                Disposed = true;
                _sha256?.Dispose();
                _sha512?.Dispose();
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}