using System;
using System.Collections.Generic;
using Xunit;

namespace PH.PicoCrypt2.Test
{
    public class AesCryptAndDecryptTest
    {
        [Fact]
        public void CryptAStringReturnValue()
        {
            var s = "a string";
            var p = "a password";

            IPicoCrypt a        = new AesCrypt();
            bool       disposed = a.Disposed;

            var cypherText = a.EncryptUtf8(s, p);
            var text2      = a.EncryptUtf8(s, p, p);



            Assert.Equal(cypherText, text2);
            Assert.True(disposed != true);
            Assert.NotEqual(cypherText, s);

        }

        [Fact]
        public void DeCryptAStringReturnValue()
        {
            var exptected = "a string";
            var s         = "zQIcqlKjN9euhZdHbNo6aQ==";
            var p         = "a password";

            IPicoCrypt a = new AesCrypt();

            var plainText = a.DecryptUtf8(s, p);




            Assert.Equal(exptected, plainText);

        }

        [Fact]
        public void TestHash1()
        {
            var s = "a string";

            IPicoCrypt a    = new AesCrypt();
            var        h256 = a.GenerateSha256String(s);
            var        h512 = a.GenerateSha512String(s);

            Assert.NotEqual(h256, h512);

        }

        [Fact]
        public void TestHash2()
        {
            var v256 = "C0DC86EFDA0060D4084098A90EC92B3D4AA89D7F7E0FBA5424561D21451E1758";
            var v512 =
                "D9F28C8B153EE8916C7F8FAAA9D94BB04D06DA7616034A4CD7E03102E30FA67CFA8EEE1E7AFBC7D3A5909285E41B24B16E08B2F7338D15398554407CF7025B45";

            var    s      = "a string";
            string h256_0 = "";
            string h512_0 = "";

            using (IPicoCrypt a = new AesCrypt())
            {
                h256_0 = a.GenerateSha256String(s);
                h512_0 = a.GenerateSha512String(s);
            }

            string h256_1 = "";
            string h512_1 = "";

            using (IPicoCrypt a1 = new AesCrypt())
            {
                h256_1 = a1.GenerateSha256String(s);
                h512_1 = a1.GenerateSha512String(s);
            }

            Assert.Equal(v256, h256_0);
            Assert.Equal(v256, h256_1);

            Assert.Equal(v512, h512_0);
            Assert.Equal(v512, h512_1);





        }


        [Fact]
        public void ErrorHandling()
        {
            var s = "a string";
            var p = "a password";

            IPicoCrypt a = new AesCrypt();

            var chyper = a.EncryptUtf8(s, p, s);

            var error0 = a.DecryptUtf8(chyper, s, s);
            var good   = a.DecryptUtf8(chyper, p, s);

            Exception exc = null;
            try
            {
                var error2 = a.DecryptUtf8(chyper, "a bad password", "a bad salt", true);
            }
            catch (Exception e)
            {
                exc = e;
            }

            Assert.Null(error0);
            Assert.NotNull(exc);
            Assert.Equal(s, good);


        }


        [Fact]
        public void GenerateRandomStrings()
        {

            IPicoCrypt a = new AesCrypt();

            var s = a.GenerateRandomString(7);

            var onlyNumbers = a.GenerateRandomString(5, RandomStringMode.OnlyNumbers);
            var i           = Convert.ToInt32(onlyNumbers);

            Assert.True(s.Length == 7);
            Assert.Equal(onlyNumbers, $"{i}");

        }
    }

}
