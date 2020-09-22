using System;
using System.Text;
using Xunit;

namespace PH.PicoCrypt2.Test
{
    public class Md5Test
    {
        [Fact]
        public void TestingNullDataThrowExceptions()
        {
            IPicoCrypt a         = new AesCrypt();
            //Exception  e0        = null;
            //Exception  e1        = null;
            Exception  e2        = null;
            Exception  e3        = null;
            byte[]     nullBytes = null;
            //try
            //{
            //    a.CalculateMd5Hash(nullBytes);
            //}
            //catch (Exception e)
            //{
            //    e0 = e;
            //}

            //try
            //{
            //    a.CalculateMd5Hash(string.Empty);
            //}
            //catch (Exception e)
            //{
            //    e1 = e;
            //}

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


            //Assert.NotNull(e0);
            //Assert.NotNull(e1);
            Assert.NotNull(e2);
            Assert.NotNull(e3);
        }

        [Fact]
        public void TestingMd5Hash()
        {
            IPicoCrypt a = new AesCrypt();

            var str = "A";
            var md5 = "7fc56270e7a70fa81a5935b72eacbe29";
            var mdb = Encoding.UTF8.GetBytes(md5);


            var res0 = a.CalculateMd5HashString(Encoding.UTF8.GetBytes(str));
            var res1 = a.CalculateMd5HashString(str);

            //var res2 = a.CalculateMd5Hash(Encoding.UTF8.GetBytes(str));
            //var res3 = a.CalculateMd5Hash(str);


            Assert.Equal(md5, res0);
            Assert.Equal(md5, res1);
            //Assert.Equal(mdb, res2);
            //Assert.Equal(mdb, res3);

        }
    }
}