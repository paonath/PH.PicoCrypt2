using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace PH.PicoCrypt2
{
    /// <summary>
    /// Crypt Service
    /// </summary>
    /// <seealso cref="System.IDisposable" />
    public interface IPicoCrypt : IDisposable
    {
        /// <summary>
        /// True if disposed instance
        /// </summary>
        bool Disposed { get; }

        /// <summary>
        /// Encrypt a UTF8 text
        /// </summary>
        /// <param name="plainText">text to encrypt</param>
        /// <param name="password">cypher password</param>
        /// <returns>encrypted text</returns>
        string EncryptUtf8(string plainText, string password);

        /// <summary>
        /// Encrypt a UTF8 text
        /// </summary>
        /// <param name="plainText">text to encrypt</param>
        /// <param name="password">cypher password</param>
        /// <param name="salt">cypher salt</param>
        /// <returns></returns>
        string EncryptUtf8(string plainText, string password, string salt);

        // <summary>
        // Decrpyt a UTF8 text
        // </summary>
        // <param name="encryptedText">UTF8 text encrypted</param>
        // <param name="password">cypher password</param>
        // <returns>plain text</returns>

        /// <summary>
        /// Decrpyt a UTF8 text
        /// </summary>
        /// <param name="encryptedText">UTF8 text encrypted</param>
        /// <param name="password">cypher password</param>
        /// <param name="throwOnError">if True on error throw exception, otherwise return string null</param>
        /// <returns>plain text or null</returns>
        string DecryptUtf8(string encryptedText, string password, bool throwOnError = false);

        /// <summary>
        /// Decrpyt a UTF8 text
        /// </summary>
        /// <param name="encryptedText">UTF8 text encrypted</param>
        /// <param name="password">cypher password</param>
        /// <param name="salt">cypher salt</param>
        /// <param name="throwOnError">if True on error throw exception, otherwise return string null</param>
        /// <returns>plain text or null</returns>
        string DecryptUtf8(string encryptedText, string password, string salt, bool throwOnError = false);

        /// <summary>
        /// Generate a Random string value
        /// </summary>
        /// <param name="length">string length</param>
        /// <param name="mode">random mode</param>
        /// <returns></returns>
        string GenerateRandomString(int length, RandomStringMode mode = RandomStringMode.Full);

        /// <summary>
        /// Generate a Random string value excluding given values
        /// </summary>
        /// <param name="length">string length</param>
        /// <param name="excludeValues">string to exclude</param>
        /// <param name="mode">random mode</param>
        /// <returns>a random string</returns>
        string GenerateRandomString(int length,List<string> excludeValues, RandomStringMode mode = RandomStringMode.Full);

        /// <summary>
        /// Generate a Random string value excluding given regex pattern
        /// </summary>
        /// <param name="length">string length</param>
        /// <param name="excludePattern">pattern for exclusion</param>
        /// <param name="mode">random mode</param>
        // <returns>a random string</returns>
        string GenerateRandomString(int length, Regex excludePattern, RandomStringMode mode = RandomStringMode.Full);

        /// <summary>
        /// Generate a Random string value excluding given values and pattern
        /// </summary>
        /// <param name="length">string length</param>
        /// <param name="excludeValues">string to exclude</param>
        /// <param name="excludePattern">pattern for exclusion</param>
        /// <param name="mode">random mode</param>
        /// <returns>a random string</returns>
        string GenerateRandomString(int length,List<string> excludeValues, Regex excludePattern, RandomStringMode mode = RandomStringMode.Full);


        /// <summary>
        /// Encode Base 64 string from plain text
        /// </summary>
        /// <param name="plainText">text to encode</param>
        /// <returns>base64 encoded string</returns>
        string Base64Encode(string plainText);

        /// <summary>
        /// Decode a Base 64 string
        /// </summary>
        /// <param name="base64EncodedData">base64 encoded string</param>
        /// <returns>plain text</returns>
        string Base64Decode(string base64EncodedData);

        /// <summary>
        /// Computes the hash value for the specified string returning as string 
        /// </summary>
        /// <param name="inputValue">string to be hashed</param>
        /// <returns>hash string</returns>
        string GenerateSha256String(string inputValue);

        /// <summary>
        /// Computes the hash value for the specified string returning as string 
        /// </summary>
        /// <param name="inputValue">string to be hashed</param>
        /// <returns>hash string</returns>
        string GenerateSha512String(string inputValue);

    }
}