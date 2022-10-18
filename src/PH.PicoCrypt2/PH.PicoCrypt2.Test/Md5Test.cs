using System;
using System.IO;
using System.Text;
using System.Threading;
using Xunit;

namespace PH.PicoCrypt2.Test
{
    public class Md5Test
    {
        [Fact]
        public void TestingNullDataThrowExceptions()
        {
            IPicoCrypt a         = new AesCrypt();
            Exception  e2        = null;
            Exception  e3        = null;
            byte[]     nullBytes = null;
            
            try
            {
                a.CalculateMd5HashString(string.Empty);
            }
            catch (Exception e)
            {
                e2 = e;
            }
            try
            {
                a.CalculateMd5HashString(nullBytes);
            }
            catch (Exception e)
            {
                e3 = e;
            }

      
            Assert.NotNull(e2);
            Assert.NotNull(e3);
        }

        [Fact]
        public void TestingMd5Hash()
        {
            
            using (IPicoCrypt a = new AesCrypt())
            {
	            var str = "A";
	            var md5 = "7fc56270e7a70fa81a5935b72eacbe29";
	           

	            var res0 = a.CalculateMd5HashString(Encoding.UTF8.GetBytes(str));
	            var res1 = a.CalculateMd5HashString(str);


	            Assert.Equal(md5, res0);
	            Assert.Equal(md5, res1);
	            
            }

           
           

        }

        [Fact]
        public async void TestMd5StreamAsync()
        {
	        using IPicoCrypt a        = new AesCrypt();
	        var              str      = "A";
	        var              md5      = "7fc56270e7a70fa81a5935b72eacbe29";
	      


	        var aBytes = Encoding.UTF8.GetBytes(str);

	        var s              = GenerateStreamFromString(str);
	       
	       
	        var res1           = await a.GetMd5HashStringFromStreamAsync(s, CancellationToken.None);

	        
	        Assert.Equal(md5, res1);

        }

        public static Stream GenerateStreamFromString(string s)
        {
	        var stream = new MemoryStream();
	        var writer = new StreamWriter(stream);
	        writer.Write(s);
	        writer.Flush();
	        stream.Position = 0;
	        return stream;
        }
    }
}