/*
 * (C) 2018 José Hurtado
 * 
 * EN: Crypto hash algorithm interface and factory
 * ES: Definición de cripto algoritmo de hash y factoría
 * 
 * Licencia: para este archivo se aplica: https://opensource.org/licenses/MIT
 */
namespace qrypu.Core.Crypto
{
    using System;

    /// <summary>
    /// Hash algorithms supported
    /// </summary>
    public enum CryptoHashName : byte
    {
        Sha256 = 0,
        Sha1 = 1,
        Sha512 = 2,
        Sha384 = 3,
        Blake256 = 4,
        Blake224 = 5,
        Blake512 = 6,
        Blake384 = 7,
        Groestl256 = 8,
        Groestl224 = 9,
        Groestl512 = 10,
        Groestl384 = 11,
        JH256 = 12,
        JH224 = 13,
        JH512 = 14,
        JH384 = 15,
        Skein256 = 16,
        Skein224 = 17,
        Skein512 = 18,
        Skein384 = 19
    }

    /// <summary>
    /// Hash algorithm contract
    /// </summary>
    public interface ICryptoHash
    {
        /// <summary>
        /// Config hash. Call one time per result bit length and compute any number of messages.
        /// </summary>
        /// <param name="bitLen">Result hash bit length</param>
        void Config(int bitLen);

        /// <summary>
        /// Compute hash
        /// </summary>
        /// <param name="source">Stream or buffer</param>
        /// <returns>Hash resultant</returns>
        byte[] Compute(HashMessageSource source);
    }

    /// <summary>
    /// Hash algorithm factory
    /// </summary>
    public static class CryptoHashFactory
    {
        public static ICryptoHash Create(CryptoHashName hash)
        {
            switch (hash)
            {
                case CryptoHashName.Sha256:
                    return SHA.Create(256);
                case CryptoHashName.Sha1:
                    return SHA.Create(160);
                case CryptoHashName.Sha512:
                    return SHA.Create(512);
                case CryptoHashName.Sha384:
                    return SHA.Create(384);
                case CryptoHashName.Blake256:
                    return Blake.Create(256);
                case CryptoHashName.Blake224:
                    return Blake.Create(224);
                case CryptoHashName.Blake512:
                    return Blake.Create(512);
                case CryptoHashName.Blake384:
                    return Blake.Create(384);
                case CryptoHashName.Groestl256:
                    return Groestl.Create(256);
                case CryptoHashName.Groestl224:
                    return Groestl.Create(224);
                case CryptoHashName.Groestl512:
                    return Groestl.Create(512);
                case CryptoHashName.Groestl384:
                    return Groestl.Create(384);
                case CryptoHashName.JH256:
                    return JH.Create(256);
                case CryptoHashName.JH224:
                    return JH.Create(224);
                case CryptoHashName.JH512:
                    return JH.Create(512);
                case CryptoHashName.JH384:
                    return JH.Create(384);
                case CryptoHashName.Skein256:
                    return Skein.Create(256);
                case CryptoHashName.Skein224:
                    return Skein.Create(224);
                case CryptoHashName.Skein512:
                    return Skein.Create(512);
                case CryptoHashName.Skein384:
                    return Skein.Create(384);
                default:
                    throw new ArgumentException();
            }
        }
    }
}