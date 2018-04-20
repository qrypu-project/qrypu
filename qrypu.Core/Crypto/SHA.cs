using System;
using System.IO;
using System.Security.Cryptography;

namespace qrypu.Core.Crypto
{
    public class SHA : ICryptoHash
    {
        private HashAlgorithm _sha;

        public static SHA Create(int bitLen)
        {
            if ((bitLen != 160) && (bitLen != 256) && (bitLen != 384) && (bitLen != 512))
                throw new ArgumentException();

            SHA result = new SHA();

            result.Config(bitLen);
            return result;
        }

        public byte[] Compute(HashMessageSource source)
        {
            using (var stream = new MemoryStream())
            {
                int count = 0;
                var buffer = new byte[1024];
                while ((count = source.Read(buffer, 0, 1024)) > 0)
                    stream.Write(buffer, 0, count);

                stream.Seek(0, SeekOrigin.Begin);
                return this._sha.ComputeHash(stream);
            }
        }

        public void Config(int bitLen)
        {
            switch (bitLen)
            {
                case 160: 
                    _sha = SHA1.Create();
                    break;
                case 256:
                    _sha = SHA256.Create();
                    break;
                case 384:
                    _sha = SHA384.Create();
                    break;
                case 512:
                    _sha = SHA512.Create();
                    break;
                default:
                    throw new ArgumentException();
            }
        }
    }
}