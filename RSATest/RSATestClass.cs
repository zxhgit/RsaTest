using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace RSATest
{
    public class RsaTestClass
    {
        #region TestCase

        #region StrSource
        //private const string StrSource = @"declare @phone varchar(15);
        //                                declare @name varchar(40);
        //                                declare @phone400 int;
        //                                declare @virtualphone int;
        //                                declare @flag  smallint;  ---1:400电话 2：虚拟电话  0：电话
        //                                set @flag=0;

        //                                select @phone=Phone,@name=Name from DealerSales WITH(NOLOCK) where SalesId=@linkId;  --普通

        //                                select @phone400=callcenteropenstatus,@virtualphone=virtualnumopenstatus from Dealers WITH(NOLOCK) where  DealerId=@dealerId;

        //                                if @phone400=15 --400电话
        //                                begin
	       //                                 select @phone=a.CallNum 
	       //                                 from(
		      //                                  SELECT ISNULL((SELECT CCPPNUM FROM CallCenter400PhonePool WITH(NOLOCK) WHERE CCDR.ccppid=CallCenter400PhonePool.ccppid ),'') CallNum
		      //                                  FROM CallCenterSales400PoolRel AS CCDR WITH(NOLOCK) WHERE CCDR.linkmanid=@linkId and CCDR.sprstatus=@ccdrstatus) as a
                   
	       //                                 set @flag=1;
        //                                end
        //                                else if @phone400=10 --400电话 0-未开通，10-已开通
        //                                begin
	       //                                 select @phone=a.CallNum 
	       //                                 from(
		      //                                  SELECT ISNULL((SELECT CCPPNUM FROM CallCenter400PhonePool WITH(NOLOCK) WHERE CCDR.ccppid=CallCenter400PhonePool.ccppid),'') CallNum
		      //                                  FROM CallCenter400DealerRel AS CCDR WITH(NOLOCK) WHERE CCDR.ccdrstatus=@ccdrstatus AND CCDR.dealerid=@dealerId) as a
                   
	       //                                 set @flag=1;
        //                                end
        //                                else if @virtualphone=10  --虚拟电话 10已开通
        //                                begin
        //                                    select @phone= Pl.vnpnumber from CallCenterSalesVirtualNumberPollRel as PollRel with(nolock) inner join CallCenterVirtualNumberPool as Pl with(nolock) 
        //                                    on Pl.vnpid=PollRel.vnpid
        //                                    where PollRel.linkmanid=@linkId and dealerid=@dealerId and svnprstatus=@svnprstatus
        //                                    set @flag=2;                   
        //                                end
  
        //                                select @phone as phone,@name as name ,@flag as flag";

        private const string StrSource =
            "由于京东很多页面内容是异步加载的，像首页、单品等系统有许多第三方异步接口调用，使用后端程序抓取到的页面数据是同步的，并不能取到动态的 JavaScript 渲染的内容，所以就必须使用像 PhantomJS 这种能模拟浏览器的工具";

        private const string KeyPairPath = @"E:\mycode\RSATest\RSATest\keyfile\keypair.xml";

        private const string PublicKeyPath = @"E:\mycode\RSATest\RSATest\keyfile\publickey.xml";

        #endregion

        /// <summary>
        /// 生成公钥私钥测试
        /// </summary>
        public static void CreateKeysTest()
        {
            var test = new RsaTestClass();
            test.RsaKey(KeyPairPath, PublicKeyPath);
        }

        /// <summary>
        /// 公钥加密私钥解密测试，结果能正确解密，RSA可逆
        /// </summary>
        public static void EncryptTest()
        {
            var test = new RsaTestClass();
            var hashStr = test.GetHash(StrSource);
            var publicKeyXmlStr = test.ReadPublicKey(PublicKeyPath);
            var encryptStr =
                test.RsaEncrypt(publicKeyXmlStr, hashStr);
            var privateKeyXmlStr = test.ReadPrivateKey(KeyPairPath);
            var decryptStr = test.RsaDecrypt(privateKeyXmlStr, encryptStr);
            var isEqure = hashStr == decryptStr;
        }

        /// <summary>
        /// 签名测试，对摘要用私钥签名，然后用公钥和摘要验证该签名
        /// </summary>
        public static void SignatureTest()
        {
            var test = new RsaTestClass();
            var hashStr = test.GetHash(StrSource);
            //故意改变原始字符串，反向测试
            var hashStr1 = test.GetHash(StrSource + "--a");
            //对hashString进行签名
            var privateKeyXmlStr = test.ReadPrivateKey(KeyPairPath);
            var signatureStr = test.SignatureFormatter(privateKeyXmlStr, hashStr);
            //验证签名
            var publicKeyXmlStr= test.ReadPublicKey(PublicKeyPath);
            var checkRes1 = test.SignatureDeformatter(publicKeyXmlStr, hashStr, signatureStr);
            var checkRes2 = test.SignatureDeformatter(publicKeyXmlStr, hashStr1, signatureStr);
        }

        /// <summary>
        /// test hash
        /// </summary>
        public static void TestHash()
        {
            var algorithm = HashAlgorithm.Create("MD5");
            var bytes = Encoding.GetEncoding("utf-8").GetBytes(StrSource);
            var inArray = algorithm.ComputeHash(bytes);
            var sb = new StringBuilder(32);
            foreach (var t in inArray)
            {
                sb.Append(t.ToString("x").PadLeft(2, '0'));
            }
            //此处得到的值与 https://1024tools.com/hash 结果相同，注：该网站用的是utf-8非gb2312
            var str = sb.ToString().ToUpper();
        }

        #endregion

        private void RsaKey(string keyPairPath, string publicKeyPath)
        {
            var provider = new RSACryptoServiceProvider();
            CreateKeyPairXml(keyPairPath, provider.ToXmlString(true));
            CreatePublicKeyXml(publicKeyPath, provider.ToXmlString(false));
        }

        /// <summary>
        /// 创建公钥文件
        /// </summary>
        /// <param name="path"></param>
        /// <param name="publickey"></param>
        private void CreatePublicKeyXml(string path, string publickey)
        {
            var publickeyxml = new FileStream(path, FileMode.Create);
            var sw = new StreamWriter(publickeyxml);
            sw.WriteLine(publickey);
            sw.Close();
            publickeyxml.Close();
        }
        /// <summary>
        /// 创建公钥私钥文件
        /// </summary>
        /// <param name="path"></param>
        /// <param name="privatekey"></param>
        private void CreateKeyPairXml(string path, string privatekey)
        {
            var privatekeyxml = new FileStream(path, FileMode.Create);
            var sw = new StreamWriter(privatekeyxml);
            sw.WriteLine(privatekey);
            sw.Close();
            privatekeyxml.Close();
        }

        /// <summary>
        /// 读取公钥
        /// </summary>
        /// <param name="path"></param>
        /// <returns></returns>
        private string ReadPublicKey(string path)
        {
            var reader = new StreamReader(path);
            var publickey = reader.ReadToEnd();
            reader.Close();
            return publickey;
        }
        /// <summary>
        /// 读取私钥
        /// </summary>
        /// <param name="path"></param>
        /// <returns></returns>
        private string ReadPrivateKey(string path)
        {
            var reader = new StreamReader(path);
            var privatekey = reader.ReadToEnd();
            reader.Close();
            return privatekey;
        }

        /// <summary>
        /// 对原始数据进行MD5加密
        /// </summary>
        /// <param name="mStrSource">待加密数据</param>
        /// <returns>返回机密后的数据</returns>
        private string GetHash(string mStrSource)
        {
            var algorithm = HashAlgorithm.Create("MD5");
            var bytes = Encoding.GetEncoding("GB2312").GetBytes(mStrSource);
            var inArray = algorithm.ComputeHash(bytes);            
            return Convert.ToBase64String(inArray);
        }

        /// <summary>
        /// RSA加密
        /// </summary>
        /// <param name="xmlPublicKey">公钥</param>
        /// <param name="mStrEncryptString">MD5加密后的数据</param>
        /// <returns>RSA公钥加密后的数据</returns>
        public string RsaEncrypt(string xmlPublicKey, string mStrEncryptString)
        {
            var provider = new RSACryptoServiceProvider();
            provider.FromXmlString(xmlPublicKey);
            var bytes = new UnicodeEncoding().GetBytes(mStrEncryptString);
            var str2 = Convert.ToBase64String(provider.Encrypt(bytes, false));
            return str2;
        }
        /// <summary>
        /// RSA解密
        /// </summary>
        /// <param name="xmlPrivateKey">私钥</param>
        /// <param name="mStrDecryptString">待解密的数据</param>
        /// <returns>解密后的结果</returns>
        public string RsaDecrypt(string xmlPrivateKey, string mStrDecryptString)
        {
            var provider = new RSACryptoServiceProvider();
            provider.FromXmlString(xmlPrivateKey);
            var rgb = Convert.FromBase64String(mStrDecryptString);
            var buffer2 = provider.Decrypt(rgb, false);
            var str2 = new UnicodeEncoding().GetString(buffer2);
            return str2;
        }

        /// <summary>
        /// 对MD5加密后的密文进行签名
        /// </summary>
        /// <param name="pStrKeyPrivate">私钥</param>
        /// <param name="mStrHashbyteSignature">MD5加密后的密文</param>
        /// <returns></returns>
        public string SignatureFormatter(string pStrKeyPrivate, string mStrHashbyteSignature)
        {
            var rgbHash = Convert.FromBase64String(mStrHashbyteSignature);
            var key = new RSACryptoServiceProvider();
            key.FromXmlString(pStrKeyPrivate);
            var formatter = new RSAPKCS1SignatureFormatter(key);
            formatter.SetHashAlgorithm("MD5");
            var inArray = formatter.CreateSignature(rgbHash);
            return Convert.ToBase64String(inArray);
        }

        /// <summary>
        /// 签名验证
        /// </summary>
        /// <param name="pStrKeyPublic">公钥</param>
        /// <param name="pStrHashbyteDeformatter">待验证的用户名</param>
        /// <param name="pStrDeformatterData">注册码</param>
        /// <returns></returns>
        public bool SignatureDeformatter(string pStrKeyPublic, string pStrHashbyteDeformatter, string pStrDeformatterData)
        {
            try
            {
                var rgbHash = Convert.FromBase64String(pStrHashbyteDeformatter);
                var key = new RSACryptoServiceProvider();
                key.FromXmlString(pStrKeyPublic);
                var deformatter = new RSAPKCS1SignatureDeformatter(key);
                deformatter.SetHashAlgorithm("MD5");
                var rgbSignature = Convert.FromBase64String(pStrDeformatterData);
                return deformatter.VerifySignature(rgbHash, rgbSignature);
            }
            catch
            {
                return false;
            }
        }
    }
}
