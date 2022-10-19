#region

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using JetBrains.Annotations;

#endregion

namespace PH.PicoCrypt2
{
	/// <summary>
	///   Crypt Service implementation based on AES Alg.
	/// </summary>
	/// <seealso cref="PH.PicoCrypt2.IAesCrypt" />
	/// <seealso cref="System.IDisposable" />
	public class AesCrypt : IAesCrypt
	{
		private readonly Random       _r;
		private readonly Lazy<SHA256> _sha256;
		private readonly Lazy<SHA512> _sha512;
		private readonly Lazy<MD5>    _md5;
		private          bool         _safeWeb;


		/// <summary>
		///   Initializes a new instance of the <see cref="AesCrypt" /> class.
		/// </summary>
		public AesCrypt()
		{
			_r       = new Random();
			_sha256  = new Lazy<SHA256>(() => SHA256.Create());
			_sha512  = new Lazy<SHA512>(() => SHA512.Create());
			_md5     = new Lazy<MD5>(() => MD5.Create());
			Disposed = false;
			_safeWeb = false;
		}

		/// <summary>
		///   Gets a value indicating whether this <see cref="AesCrypt" /> is disposed.
		/// </summary>
		/// <value><c>true</c> if disposed; otherwise, <c>false</c>.</value>
		public bool Disposed { get; private set; }

		/// <summary>Encrypt a UTF8 text</summary>
		/// <param name="plainText">text to encrypt</param>
		/// <param name="password">cypher password</param>
		/// <returns>encrypted text</returns>
		/// <exception cref="ArgumentException">
		///   Value cannot be null or empty or WhiteSpace. - plainText
		///   or
		///   Value cannot be null or empty or WhiteSpace. - password
		/// </exception>
		[NotNull]
		public string EncryptUtf8([NotNull] string plainText, [NotNull] string password) =>
			EncryptUtf8(plainText, password, password);


		/// <summary>Encrypt a UTF8 text</summary>
		/// <param name="plainText">text to encrypt</param>
		/// <param name="password">cypher password</param>
		/// <param name="salt">cypher salt</param>
		/// <returns>encrypted text</returns>
		/// <exception cref="ArgumentException">
		///   Value cannot be null or empty or WhiteSpace. - plainText
		///   or
		///   Value cannot be null or empty or WhiteSpace. - password
		///   or
		///   Value cannot be null or empty or WhiteSpace. - salt
		/// </exception>
		[NotNull]
		public string EncryptUtf8([NotNull] string plainText, [NotNull] string password, [NotNull] string salt)
		{
			if (string.IsNullOrEmpty(plainText) || string.IsNullOrWhiteSpace(plainText))
			{
				throw new ArgumentException("Value cannot be null or empty or WhiteSpace.", nameof(plainText));
			}

			if (string.IsNullOrEmpty(password) || string.IsNullOrWhiteSpace(password))
			{
				throw new ArgumentException("Value cannot be null or empty or WhiteSpace.", nameof(password));
			}

			if (string.IsNullOrEmpty(salt) || string.IsNullOrWhiteSpace(salt))
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
		public string DecryptUtf8(string encryptedText, string password, bool throwOnError = false) =>
			DecryptUtf8(encryptedText, password, password, throwOnError);

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
									while ((count = decryptedData.Read(buffer, 0, buffer.Length)) != 0)
									{
										dataOut.Write(buffer, 0, count);
									}

									return Encoding.UTF8.GetString(dataOut.ToArray());
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
		public string DecryptUtf8(string encryptedText, string password, string salt, bool throwOnError = false) =>
			PrivateDecryptUtf8(encryptedText, password, salt, throwOnError);


		/// <summary>Generate a Random string value</summary>
		/// <param name="length">string length</param>
		/// <param name="mode">random mode</param>
		/// <returns></returns>
		[NotNull]
		public string GenerateRandomString(int length, RandomStringMode mode = RandomStringMode.Full) =>
			GenerateRandomString(length, new List<string>(), mode);

		/// <summary>
		///   Generate a Random string value safe for use with url or html, etc.
		/// </summary>
		/// <param name="length">string length</param>
		/// <param name="mode">random mode</param>
		/// <returns></returns>
		[NotNull]
		public string GenerateRandomStringSafeForWebAndUrl(int length, RandomStringMode mode = RandomStringMode.Full)
		{
			_safeWeb = true;
			var r = GenerateRandomString(length, mode);
			_safeWeb = false;
			return r;
		}

		[NotNull]
		private string PrivateGenerateRandomString(int length, RandomStringMode mode)
		{
			if (length == 0)
			{
				return string.Empty;
			}

			var result = "";

			using (var provider = new RNGCryptoServiceProvider())
			{
				switch (mode)
				{
					case RandomStringMode.Full:

						#region FULL

						var b = length % 4;
						var m = length / 4;

						var nums0    = GetRandomNumbersOnly(provider, m);
						var charsUp0 = GetRandomUpperCharactersOnly(provider, m);
						var charsLo0 = GetRandomLowerCharactersOnly(provider, m);
						var syms0    = GetRandomSymbolsOnly(provider, m, _safeWeb);
						var s        = Shuffle($"{nums0}{charsUp0}{charsLo0}{syms0}");
						result = $"{GetRandomUpperCharactersOnly(provider, b)}{s}";

						#endregion

						break;
					case RandomStringMode.CharactersOnly:

						#region CharactersOnly

						var b0      = length % 2;
						var charsUp = GetRandomUpperCharactersOnly(provider, length / 2);
						var charsLo = GetRandomLowerCharactersOnly(provider, length / 2);
						var pre     = "";
						if (b0 > 0)
						{
							pre = GetRandomUpperCharactersOnly(provider, b0);
						}

						result = Shuffle($"{pre}{charsLo}{charsUp}");

						#endregion

						break;
					case RandomStringMode.CharacterAndNumbers:

						#region CharacterAndNumbers

						var b1 = length % 3;
						var mi = length / 3;

						var nums1    = GetRandomNumbersOnly(provider, mi);
						var charsUp1 = GetRandomUpperCharactersOnly(provider, mi);
						var charsLo1 = GetRandomLowerCharactersOnly(provider, mi);
						var pre1     = "";
						if (b1 > 0)
						{
							pre1 = GetRandomUpperCharactersOnly(provider, b1);
						}

						var sh1 = Shuffle($"{nums1}{charsUp1}{charsLo1}");

						result = $"{pre1}{sh1}";

						#endregion

						break;
					case RandomStringMode.SymbolsAndNumbers:

						#region SymbolsAndNumbers

						var b2 = length % 2;
						var m2 = length / 2;

						var nums2 = GetRandomNumbersOnly(provider, m2);
						var syms2 = GetRandomSymbolsOnly(provider, m2, _safeWeb);

						var pre2 = "";
						if (b2 > 0)
						{
							pre2 = GetRandomNumbersOnly(provider, b2);
						}

						var sh2 = Shuffle($"{nums2}{syms2}");

						result = $"{pre2}{sh2}";

						#endregion

						break;
					case RandomStringMode.OnlySymbols:
						result = GetRandomSymbolsOnly(provider, length, _safeWeb);
						break;
					case RandomStringMode.OnlyNumbers:
						result = GetRandomNumbersOnly(provider, length);
						break;
					default:
						throw new ArgumentOutOfRangeException(nameof(mode), mode, null);
				}
			}

			return result;
		}


		///// <summary>Privates the generate random string.</summary>
		///// <param name="length">The length.</param>
		///// <param name="mode">The mode.</param>
		///// <returns></returns>
		///// <exception cref="ArgumentOutOfRangeException">mode - null</exception>
		//[NotNull]
		//private string PrivateGenerateRandomString(int length, RandomStringMode mode)
		//{
		//    string result = "";

		//    using (RNGCryptoServiceProvider provider = new System.Security.Cryptography.RNGCryptoServiceProvider())
		//    {
		//        switch (mode)
		//        {
		//            case RandomStringMode.Full:
		//                break;
		//            case RandomStringMode.CharactersOnly:
		//                break;
		//            case RandomStringMode.CharacterAndNumbers:
		//                break;
		//            case RandomStringMode.SymbolsAndNumbers:
		//                break;
		//            case RandomStringMode.OnlySymbols:
		//                result = GetRandomSymbolsOnly(provider, length, _safeWeb);
		//                break;
		//            case RandomStringMode.OnlyNumbers:
		//                result = GetRandomNumbersOnly(provider, length);
		//                break;
		//            default:
		//                throw new ArgumentOutOfRangeException(nameof(mode), mode, null);
		//        }
		//    }

		//    return result;

		//    /*
		//    string charsUP = "QWERTYUIOPASDFGHJKLZXCVBNM";
		//    string charsLO = "qwertyuiopasdfghjklzxcvbnm";
		//    string sims    = "|\\!\"£%&/()=?'^[]+*@#°,;.:-_<>~";
		//    string simsWeb = "-_.~$^|";
		//    string chars   = $@"QqWwEe€RrTtYyUuIiOoPpéè[*+AaSsDdFfGgHhJjKkLlçò@°à#§ù><ZzXxCcVvBbNnMm-_1!23£4$5%6&7890?ì^";
		//    string numbers = "1234567890";

		//    if (_safeWeb)
		//    {
		//        chars = simsWeb + $@"QqWwEeRrTtYyUuIiOoPpAaSsDdFfGgHhJjKkLlZzXxCcVvBbNnMm1234567890";
		//        sims = simsWeb;
		//    }

		//    switch (mode)
		//    {
		//        case RandomStringMode.Full:
		//            break;
		//        case RandomStringMode.CharactersOnly:
		//            sims    = charsLO;
		//            chars   = $"{charsUP}{charsLO}";
		//            numbers = charsUP;
		//            break;
		//        case RandomStringMode.CharacterAndNumbers:
		//            sims  = charsLO;
		//            chars = $"{charsUP}{charsLO}";
		//            break;
		//        case RandomStringMode.SymbolsAndNumbers:
		//            charsUP = sims;
		//            charsLO = numbers;
		//            chars   = $"{charsUP}{charsLO}";
		//            break;
		//        case RandomStringMode.OnlySymbols:
		//            charsUP = sims;
		//            charsLO = sims;
		//            chars   = sims;
		//            numbers = sims;
		//            break;
		//        case RandomStringMode.OnlyNumbers:
		//            charsUP = numbers;
		//            charsLO = numbers;
		//            sims    = numbers;
		//            chars   = numbers;
		//            break;
		//        default:
		//            throw new ArgumentOutOfRangeException(nameof(mode), mode, null);
		//    }


		//    var first = new String(Enumerable.Repeat(charsLO, 1)
		//                                     .Select(s => s[_r.Next(s.Length)]).ToArray());
		//    var second = new String(Enumerable.Repeat(charsUP, 1)
		//                                      .Select(s => s[_r.Next(s.Length)]).ToArray());
		//    var numberRand = new String(Enumerable.Repeat(numbers, 1)
		//                                          .Select(s => s[_r.Next(s.Length)]).ToArray());

		//    var sim = new String(Enumerable.Repeat(sims, 1)
		//                                   .Select(s => s[_r.Next(s.Length)]).ToArray());

		//    var last = "";
		//    if(length >4)
		//    {
		//        last = new string(Enumerable.Repeat(chars, length)
		//                                    .Select(s => s[_r.Next(s.Length)]).ToArray());
		//    }

		//    return $"{first}{numberRand}{sim}{second}{last}".Substring(0,length);

		//     */
		//}


		[NotNull]
		private static string Shuffle([NotNull] string orderedString)
		{
			if (orderedString.Length == 0)
			{
				return string.Empty;
			}

			var shuffled = new List<char>();
			var ordered  = orderedString.ToList();
			var random   = new Random();

			while (ordered.Any())
			{
				var p = random.Next(ordered.Count());
				shuffled.Add(ordered[p]);
				ordered.RemoveAt(p);
			}

			return string.Concat(shuffled);
		}

		[NotNull]
		private static string GetRandomInternal([NotNull] RNGCryptoServiceProvider provider, int amount, string validMatch,
		                                        string exclusions = "")
		{
			if (amount == 0)
			{
				return string.Empty;
			}

			var s = "";
			if (!string.IsNullOrEmpty(exclusions) && exclusions.Length == validMatch.Length)
			{
				exclusions = "";
			}

			var realValidMatch = validMatch;
			if (!string.IsNullOrEmpty(exclusions) && !string.IsNullOrWhiteSpace(exclusions))
			{
				realValidMatch = string.Concat(validMatch.Except(exclusions));
			}

			while (s.Length != amount)
			{
				var oneByte = new byte[1];
				provider.GetBytes(oneByte);
				var character = (char)oneByte[0];
				if (realValidMatch.Contains(character) && s.LastOrDefault() != character)
				{
					s += character;
				}
			}

			return s;
		}


		[NotNull]
		private static string GetRandomSymbolsOnly([NotNull] RNGCryptoServiceProvider provider, int amount,
		                                           bool webSafe = true,
		                                           string exclusions = "")
		{
			var r = webSafe
				        ? GetRandomSymbolsWebSafeOnly(provider, amount, exclusions)
				        : GetRandomSymbolsWebUnsafeOnly(provider, amount, exclusions);

			return r;
		}

		[NotNull]
		private static string GetRandomSymbolsWebSafeOnly([NotNull] RNGCryptoServiceProvider provider, int amount,
		                                                  string exclusions = "")
		{
			var valid = "|!^+*.-_~";
			return GetRandomInternal(provider, amount, valid, exclusions);
		}


		[NotNull]
		private static string GetRandomSymbolsWebUnsafeOnly([NotNull] RNGCryptoServiceProvider provider, int amount,
		                                                    string exclusions = "") =>
			GetRandomInternal(provider, amount, Symbols, exclusions);


		[NotNull]
		private static string GetRandomNumbersOnly([NotNull] RNGCryptoServiceProvider provider, int amount,
		                                           string exclusions = "") =>
			GetRandomInternal(provider, amount, Numbers, exclusions);

		[NotNull]
		private static string GetRandomLowerCharactersOnly([NotNull] RNGCryptoServiceProvider provider, int amount,
		                                                   string exclusions = "") =>
			GetRandomInternal(provider, amount, CharsLowercase, exclusions);

		[NotNull]
		private static string GetRandomUpperCharactersOnly([NotNull] RNGCryptoServiceProvider provider, int amount,
		                                                   string exclusions = "") =>
			GetRandomInternal(provider, amount, CharsUppercase, exclusions);

		private const string SymbolsWebSafe = "|!^+*.-_~";
		private const string Symbols        = "|\\!\"£%&/()=?'^[]+*@#°,;.:-_<>~";
		private const string Numbers        = "1234567890";
		private const string CharsUppercase = "QWERTYUIOPASDFGHJKLZXCVBNM";
		private const string CharsLowercase = "qwertyuiopasdfghjklzxcvbnm";


		/// <summary>Generate a Random string value excluding given values</summary>
		/// <param name="length">string length</param>
		/// <param name="excludeValues">string to exclude</param>
		/// <param name="mode">random mode</param>
		/// <returns>a random string</returns>
		[NotNull]
		public string GenerateRandomString(int length, [NotNull] List<string> excludeValues,
		                                   RandomStringMode mode = RandomStringMode.Full)
		{
			var randomS = PrivateGenerateRandomString(length, mode);
			if (excludeValues.Count == 0)
			{
				return randomS;
			}

			while (excludeValues.Contains(randomS))
			{
				randomS = PrivateGenerateRandomString(length, mode);
			}

			return randomS;
		}

		/// <summary>Generates the random string safe for web and URL.</summary>
		/// <param name="length">The length.</param>
		/// <param name="excludeValues">The exclude values.</param>
		/// <param name="mode">The mode.</param>
		/// <returns></returns>
		[NotNull]
		public string GenerateRandomStringSafeForWebAndUrl(int length, [NotNull] List<string> excludeValues,
		                                                   RandomStringMode mode = RandomStringMode.Full)
		{
			_safeWeb = true;
			var r = GenerateRandomString(length, excludeValues, mode);
			_safeWeb = false;
			return r;
		}


		/// <summary>Generate a Random string value excluding given regex pattern</summary>
		/// <param name="length">string length</param>
		/// <param name="excludePattern">pattern for exclusion</param>
		/// <param name="mode">random mode</param>
		/// <returns></returns>
		/// <exception cref="ArgumentNullException">excludePattern</exception>
		[NotNull]
		public string GenerateRandomString(int length, [NotNull] Regex excludePattern,
		                                   RandomStringMode mode = RandomStringMode.Full)
		{
			if (excludePattern is null)
			{
				throw new ArgumentNullException(nameof(excludePattern));
			}

			var randomS = PrivateGenerateRandomString(length, mode);

			while (excludePattern.IsMatch(randomS))
			{
				randomS = PrivateGenerateRandomString(length, mode);
			}

			return randomS;
		}

		/// <summary>Generates the random string safe for web and URL.</summary>
		/// <param name="length">The length.</param>
		/// <param name="excludePattern">The exclude pattern.</param>
		/// <param name="mode">The mode.</param>
		/// <returns></returns>
		[NotNull]
		public string GenerateRandomStringSafeForWebAndUrl(int length, [NotNull] Regex excludePattern,
		                                                   RandomStringMode mode = RandomStringMode.Full)
		{
			_safeWeb = true;
			var r = GenerateRandomString(length, excludePattern, mode);
			_safeWeb = false;
			return r;
		}


		/// <summary>
		///   Generate a Random string value excluding given values and pattern
		/// </summary>
		/// <param name="length">string length</param>
		/// <param name="excludeValues">string to exclude</param>
		/// <param name="excludePattern">pattern for exclusion</param>
		/// <param name="mode">random mode</param>
		/// <returns>a random string</returns>
		/// <exception cref="ArgumentNullException">excludePattern</exception>
		/// <exception cref="ArgumentException">Value cannot be an empty collection. - excludeValues</exception>
		[NotNull]
		public string GenerateRandomString(int length, [NotNull] List<string> excludeValues,
		                                   [NotNull] Regex excludePattern,
		                                   RandomStringMode mode = RandomStringMode.Full)
		{
			if (excludePattern is null)
			{
				throw new ArgumentNullException(nameof(excludePattern));
			}

			if (excludeValues.Count == 0)
			{
				throw new ArgumentException("Value cannot be an empty collection.", nameof(excludeValues));
			}

			var randomS = PrivateGenerateRandomString(length, mode);

			while (excludePattern.IsMatch(randomS) || excludeValues.Contains(randomS))
			{
				randomS = PrivateGenerateRandomString(length, mode);
			}

			return randomS;
		}

		/// <summary>Generates the random string safe for web and URL.</summary>
		/// <param name="length">The length.</param>
		/// <param name="excludeValues">The exclude values.</param>
		/// <param name="excludePattern">The exclude pattern.</param>
		/// <param name="mode">The mode.</param>
		/// <returns></returns>
		[NotNull]
		public string GenerateRandomStringSafeForWebAndUrl(int length, [NotNull] List<string> excludeValues,
		                                                   [NotNull] Regex excludePattern,
		                                                   RandomStringMode mode = RandomStringMode.Full)
		{
			_safeWeb = true;
			var r = GenerateRandomString(length, excludeValues, excludePattern, mode);
			_safeWeb = false;
			return r;
		}

		/// <summary>Shuffles the string.</summary>
		/// <param name="orderedString">The ordered string.</param>
		/// <returns></returns>
		[NotNull]
		public string ShuffleString([NotNull] string orderedString) => Shuffle(orderedString);


		/// <summary>Gets the cipher.</summary>
		/// <param name="szKeyBase">The sz key base.</param>
		/// <param name="szIVBase">The sz iv base.</param>
		/// <returns></returns>
		[NotNull]
		private Rijndael GetCipher([NotNull] string szKeyBase, [NotNull] string szIVBase)
		{
			using (var sha = SHA256.Create())
			{
				var keySha = sha.ComputeHash(Encoding.UTF8.GetBytes(szKeyBase));
				var ivSha  = sha.ComputeHash(Encoding.UTF8.GetBytes(szIVBase));

				Rijndael r = new RijndaelManaged
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
		public string Base64Encode([NotNull] string plainText) => StringBase64Encode(plainText);

		/// <summary>Strings the base64 encode.</summary>
		/// <param name="plainText">The plain text.</param>
		/// <returns></returns>
		[NotNull]
		public static string StringBase64Encode([NotNull] string plainText)
		{
			var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
			return Convert.ToBase64String(plainTextBytes);
		}

		/// <summary>Strings the base64 decode.</summary>
		/// <param name="base64EncodedData">The base64 encoded data.</param>
		/// <returns></returns>
		[NotNull]
		public static string StringBase64Decode([NotNull] string base64EncodedData)
		{
			var base64EncodedBytes = Convert.FromBase64String(base64EncodedData);
			return Encoding.UTF8.GetString(base64EncodedBytes);
		}

		/// <summary>Decode a Base 64 string</summary>
		/// <param name="base64EncodedData">base64 encoded string</param>
		/// <returns>plain text</returns>
		[NotNull]
		public string Base64Decode([NotNull] string base64EncodedData) => StringBase64Decode(base64EncodedData);


		/// <summary>Gets the string from hash.</summary>
		/// <param name="hash">The hash.</param>
		/// <returns></returns>
		[NotNull]
		private static string GetStringFromHash([NotNull] byte[] hash)
		{
			var result = new StringBuilder();
			for (var i = 0; i < hash.Length; i++)
			{
				result.Append(hash[i].ToString("X2"));
			}

			return result.ToString();
		}

		/// <summary>
		///   Computes the hash value for the specified string returning as string
		/// </summary>
		/// <param name="inputValue">string to be hashed</param>
		/// <returns>hash string</returns>
		[NotNull]
		public string GenerateSha256String([NotNull] string inputValue)
		{
			var bytes = Encoding.UTF8.GetBytes(inputValue);
			var hash  = _sha256.Value.ComputeHash(bytes);
			return GetStringFromHash(hash);
		}

		/// <summary>
		///   Computes the hash value for the specified string returning as string
		/// </summary>
		/// <param name="inputValue">string to be hashed</param>
		/// <returns>hash string</returns>
		[NotNull]
		public string GenerateSha512String([NotNull] string inputValue)
		{
			var bytes = Encoding.UTF8.GetBytes(inputValue);
			var hash  = _sha512.Value.ComputeHash(bytes);
			return GetStringFromHash(hash);
		}

		#region MD5

		/// <summary>Converts to hex.</summary>
		/// <param name="bytes">The bytes.</param>
		/// <param name="upperCase">if set to <c>true</c> [upper case].</param>
		/// <returns></returns>
		[NotNull]
		public static string ToHex([NotNull] byte[] bytes, bool upperCase)
		{
			var result = new StringBuilder(bytes.Length * 2);

			for (var i = 0; i < bytes.Length; i++)
			{
				result.Append(bytes[i].ToString(upperCase ? "X2" : "x2"));
			}

			return result.ToString();
		}


		/// <summary>Calculates the MD5 hash.</summary>
		/// <param name="utf8StringValue">The UTF8 string value.</param>
		/// <returns></returns>
		/// <exception cref="ArgumentException">Value cannot be null or empty. - utf8StringValue</exception>
		[NotNull]
		public byte[] CalculateMd5Hash([NotNull] string utf8StringValue)
		{
			if (string.IsNullOrEmpty(utf8StringValue) || string.IsNullOrWhiteSpace(utf8StringValue))
			{
				throw new ArgumentException("Value cannot be null or empty.", nameof(utf8StringValue));
			}

			return _md5.Value.ComputeHash(Encoding.UTF8.GetBytes(utf8StringValue));
		}


		/// <summary>Calculates the MD5 hash string.</summary>
		/// <param name="utf8StringValue">The UTF8 string value.</param>
		/// <returns>MD5 hash string value</returns>
		/// <exception cref="ArgumentException">Value cannot be null or empty. - utf8StringValue</exception>
		[NotNull]
		public string CalculateMd5HashString([NotNull] string utf8StringValue)
		{
			if (string.IsNullOrEmpty(utf8StringValue) || string.IsNullOrWhiteSpace(utf8StringValue))
			{
				throw new ArgumentException("Value cannot be null or empty.", nameof(utf8StringValue));
			}

			return BitConverter.ToString(CalculateMd5Hash(utf8StringValue)).Replace("-", "").ToLower();
		}

		/// <summary>Calculates the MD5 hash.</summary>
		/// <param name="data">The data.</param>
		/// <returns></returns>
		/// <exception cref="ArgumentNullException">data</exception>
		[NotNull]
		public byte[] CalculateMd5Hash([NotNull] byte[] data)
		{
			if (data is null)
			{
				throw new ArgumentNullException(nameof(data));
			}

			return _md5.Value.ComputeHash(data);
		}

		/// <summary>Calculates the MD5 hash string.</summary>
		/// <param name="data">The data to hash.</param>
		/// <returns>MD5 hash string value</returns>
		/// <exception cref="ArgumentNullException">data</exception>
		[NotNull]
		public string CalculateMd5HashString([NotNull] byte[] data)
		{
			if (data is null)
			{
				throw new ArgumentNullException(nameof(data));
			}

			return BitConverter.ToString(CalculateMd5Hash(data)).Replace("-", "").ToLower();
		}

		/// <summary>
		///   Gets the MD5 from stream asynchronous.
		/// </summary>
		/// <param name="stream">The stream.</param>
		/// <param name="token">The token.</param>
		/// <exception cref="ArgumentNullException"></exception>
		/// <returns>MD5 hash</returns>
		public async Task<byte[]> GetMd5FromStreamAsync(Stream stream,
		                                                CancellationToken token = default(CancellationToken))
		{
			token.ThrowIfCancellationRequested();
			if (stream is null)
			{
				throw new ArgumentNullException(nameof(stream));
			}

			using (var m = new MemoryStream())
			{
				await stream.CopyToAsync(m);
				stream.Position = 0;
				m.Position      = 0;
				var aBytes = m.ToArray();
				var bytes  = CalculateMd5Hash(aBytes);
				return bytes;
			}
		}

		/// <summary>
		///   Gets the MD5 from stream.
		/// </summary>
		/// <param name="stream">The stream.</param>
		/// <returns></returns>
		public byte[] GetMd5FromStream(Stream stream) =>
			GetMd5FromStreamAsync(stream, CancellationToken.None).GetAwaiter().GetResult();


		/// <summary>
		///   Gets the MD5 hash string from stream asynchronous.
		/// </summary>
		/// <param name="stream">The stream.</param>
		/// <param name="token">The token.</param>
		/// <returns></returns>
		public async Task<string> GetMd5HashStringFromStreamAsync(Stream stream,
		                                                          CancellationToken token = default(CancellationToken))
		{
			var d = await GetMd5FromStreamAsync(stream, token);
			return BitConverter.ToString(d).Replace("-", "").ToLower();
		}

		/// <summary>
		///   Gets the MD5 hash string from stream.
		/// </summary>
		/// <param name="stream">The stream.</param>
		/// <returns></returns>
		public string GetMd5HashStringFromStream(Stream stream) =>
			GetMd5HashStringFromStreamAsync(stream, CancellationToken.None).GetAwaiter().GetResult();

		/// <summary>
		///   Gets the MD5 hash string from file asynchronous.
		/// </summary>
		/// <param name="file">The file.</param>
		/// <param name="token">The token.</param>
		/// <returns></returns>
		public async Task<string> GetMd5HashStringFromFileAsync(FileInfo file,
		                                                        CancellationToken token = default(CancellationToken))
		{
			token.ThrowIfCancellationRequested();
			if (file == null)
			{
				throw new ArgumentNullException(nameof(file));
			}

			if (!file.Exists)
			{
				throw new ArgumentException("File not found", nameof(file));
			}

			using (var inStream = new FileStream(file.FullName, FileMode.Open,
			                                     FileAccess.Read, FileShare.ReadWrite))
			{
				using (var m = new MemoryStream())
				{
					await inStream.CopyToAsync(m);
					inStream.Close();

					m.Position = 0;
					var data = await GetMd5HashStringFromStreamAsync(m, token);
					return data;
				}
			}
		}


		/// <summary>
		///   Gets the MD5 hash string from file.
		/// </summary>
		/// <param name="file">The file.</param>
		/// <returns></returns>
		public string GetMd5HashStringFromFile(FileInfo file) =>
			GetMd5HashStringFromFileAsync(file, CancellationToken.None).GetAwaiter().GetResult();

		#endregion

		/// <summary>Releases unmanaged and - optionally - managed resources.</summary>
		/// <param name="disposing">
		///   <c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only
		///   unmanaged resources.
		/// </param>
		protected virtual void Dispose(bool disposing)
		{
			if (disposing && !Disposed)
			{
				Disposed = true;
				if (_sha256.IsValueCreated)
				{
					_sha256?.Value?.Dispose();
				}

				if (_sha512.IsValueCreated)
				{
					_sha512?.Value?.Dispose();
				}

				if (_md5.IsValueCreated)
				{
					_md5?.Value?.Dispose();
				}
			}
		}

		/// <summary>
		///   Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
		/// </summary>
		public void Dispose()
		{
			Dispose(true);
			GC.SuppressFinalize(this);
		}
	}
}