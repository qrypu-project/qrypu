/*
 * (C) 2018 José Hurtado
 * 
 * ES: Implementación del algoritmo Sha2. Se agrega SHA2/224, no incorporado en .Net Standard
 * Otro objetivo es disponer del código base para futuras implementaciones híbridas.
 * 
 * Licencia: para este archivo se aplica: https://opensource.org/licenses/MIT
 */
namespace qrypu.Core.Crypto
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;

    public abstract class Sha2 : ICryptoHash
    {
        public static Sha2 Create(int bitLen)
        {
            if ((bitLen != 224) && (bitLen != 256) && (bitLen != 384) && (bitLen != 512))
                throw new ArgumentException();

            Sha2 result;
            if (bitLen == 256 || bitLen == 224)
                result = new Sha256();
            else
                result = new Sha512();

            result.Config(bitLen);
            return result;
        }

        private int _bufferLength = 0;

        /// <summary>
        /// Number of bits in hash result
        /// </summary>
        protected int _bitLen;
        public int BitLen => _bitLen;

        /// <summary>
        /// Call to set result bit len and internal mode of operation
        /// </summary>
        /// <param name="bitLen">Bit len 224, 256, 384 and 512</param>
        public void Config(int bitLen)
        {
            switch (bitLen)
            {
                case 224:
                case 256:
                    _bufferLength = 64;
                    break;
                case 384:
                case 512:
                    _bufferLength = 128;
                    break;
                default:
                    throw new ArgumentException();
            }
            this._bitLen = bitLen;
        }

        /// <summary>
        /// Initialize Hash State
        /// </summary>
        /// <param name="hashState">Hash State initialized</param>
        protected abstract void InitState(out ISha2State hashState);

        /// <summary>
        /// Compress data from buffer
        /// </summary>
        /// <param name="hashState"></param>
        /// <param name="buffer"></param>
        protected abstract void Compress(ISha2State hashState, byte[] buffer);

        protected abstract byte[] FinalHash(ISha2State hashState);

        public byte[] Compute(MessageToHashReader source)
        {
            // INIT
            // Init hash variables (in derivate class)
            var bufferLength = this._bufferLength;
            InitState(out ISha2State hashState);

            // UPDATE
            // Transform complete blocks
            byte[] buffer = new byte[bufferLength];
            UInt64 blockCount = 0;
            int bytesRead;
            while ((bytesRead = source.Read(buffer, 0, bufferLength)) == bufferLength)
            {
                Compress(hashState, buffer);
                blockCount++;
            }
            UInt64 bitLength = ((blockCount * (UInt64)bufferLength) + (UInt64)bytesRead) << 3;

            // FINAL
            // Calc extra blocks
            int blocksLeft = 1;
            if ((bytesRead + 1 + (bufferLength >> 3)) > bufferLength)
                blocksLeft++;

            // 0x80 tail and zero padding
            buffer[bytesRead] = 0x80;
            for (int p = bytesRead + 1; p < bufferLength; p++)
                buffer[p] = 0x00;

            // Process extra blocks
            if (blocksLeft > 1) // if two extra blocks
            {
                Compress(hashState, buffer);
                buffer = new byte[bufferLength];
            }
            // last extra block
            {
                byte[] length = BitConverter.GetBytes(bitLength);
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(length);
                Buffer.BlockCopy(length, 0, buffer, bufferLength - 8, 8);
                Compress(hashState, buffer);
            }

            // Finalize hash and truncate (Output Transformation)
            return FinalHash(hashState);
        }

        protected interface ISha2State { };
    }

    public class Sha256 : Sha2
    {
        /// <summary>
        /// Round constants for Sha2/224 and Sha2/256
        /// </summary>
        private static readonly UInt32[] K = new UInt32[64] {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        private class Sha256State : ISha2State
        {
            public UInt32[] H;
        }

        /// <summary>
        /// Init hsha state
        /// </summary>
        /// <param name="hashState"></param>
        protected override void InitState(out ISha2State hashState)
        {
            if (this._bitLen == 256)
                hashState = new Sha256State()
                {
                    H = new UInt32[] {
                        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
                    }
                };
            else
                hashState = new Sha256State()
                {
                    H = new UInt32[] {
                        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
                        0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
                    }
                };
        }

        protected override void Compress(ISha2State hashState, byte[] buffer)
        {
            // Init Message Schedule array (W)
            UInt32[] W = new UInt32[64];
            for (int t = 0, j = 0; t < 16; ++t, j += 4)
                W[t] = (UInt32)((buffer[j] << 24) | (buffer[j + 1] << 16) | (buffer[j + 2] << 8) | (buffer[j + 3]));
            for (int t = 16; t < 64; ++t)
                W[t] = Wsigma1(W[t - 2]) + W[t - 7] + Wsigma0(W[t - 15]) + W[t - 16];

            Sha256State state = (Sha256State)hashState;
            // Init working variables
            UInt32 a = state.H[0];
            UInt32 b = state.H[1];
            UInt32 c = state.H[2];
            UInt32 d = state.H[3];
            UInt32 e = state.H[4];
            UInt32 f = state.H[5];
            UInt32 g = state.H[6];
            UInt32 h = state.H[7];

            // 64 rounds
            for (int r = 0; r < 64; ++r)
            {
                UInt32 T1 = h + Sigma1(e) + Choice(e, f, g) + K[r] + W[r];
                UInt32 T2 = Sigma0(a) + Majority(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + T1;
                d = c;
                c = b;
                b = a;
                a = T1 + T2;
            }

            // Update hash state
            state.H[0] += a;
            state.H[1] += b;
            state.H[2] += c;
            state.H[3] += d;
            state.H[4] += e;
            state.H[5] += f;
            state.H[6] += g;
            state.H[7] += h;
        }

        protected override byte[] FinalHash(ISha2State hashState)
        {
            var size = 8;
            if (this._bitLen == 224) size = 7;
            byte[] result = new byte[size * 4];

            Sha256State state = (Sha256State)hashState;
            for (int h = 0, p = 0; h < size; h++, p += 4)
            {
                var hState = state.H[h];
                result[p + 0] = (byte)(hState >> 24);
                result[p + 1] = (byte)(hState >> 16);
                result[p + 2] = (byte)(hState >> 8);
                result[p + 3] = (byte)(hState);
            }

            return result;
        }

        private static UInt32 Choice(UInt32 x, UInt32 y, UInt32 z)
        {
            return (x & y) ^ ((~x) & z);
        }

        private static UInt32 Majority(UInt32 x, UInt32 y, UInt32 z)
        {
            return (x & y) ^ (x & z) ^ (y & z);
        }

        private static UInt32 Sigma0(UInt32 x)
        {
            return ((x >> 2) | (x << 30)) ^ ((x >> 13) | (x << 19)) ^ ((x >> 22) | (x << 10));
        }

        private static UInt32 Sigma1(UInt32 x)
        {
            return ((x >> 6) | (x << 26)) ^ ((x >> 11) | (x << 21)) ^ ((x >> 25) | (x << 7));
        }

        private static UInt32 Wsigma0(UInt32 x)
        {
            return ((x >> 7) | (x << 25)) ^ ((x >> 18) | (x << 14)) ^ (x >> 3);
        }

        private static UInt32 Wsigma1(UInt32 x)
        {
            return ((x >> 17) | (x << 15)) ^ ((x >> 19) | (x << 13)) ^ (x >> 10);
        }
    }

    public class Sha512 : Sha2
    {
        /// <summary>
        /// Round constants for Sha2/384 and Sha2/512
        /// </summary>
        private static readonly UInt64[] K = new UInt64[80] {
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
            0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
            0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
            0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
            0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
            0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
            0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
            0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
            0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
            0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
            0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
            0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
            0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
        };

        private class Sha512State : ISha2State
        {
            public UInt64[] H;
        }

        /// <summary>
        /// Init hsha state
        /// </summary>
        /// <param name="hashState"></param>
        protected override void InitState(out ISha2State hashState)
        {
            if (this._bitLen == 512)
                hashState = new Sha512State()
                {
                    H = new UInt64[] {
                        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
                    }
                };
            else
                hashState = new Sha512State()
                {
                    H = new UInt64[] {
                        0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
                        0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
                    }
                };
        }

        protected override void Compress(ISha2State hashState, byte[] buffer)
        {
            // Init Message Schedule array (W)
            UInt64[] W = new UInt64[80];
            for (int t = 0, j = 0; t < 16; ++t, j += 8)
                W[t] = ((UInt64)buffer[j    ] << 56) | ((UInt64)buffer[j + 1] << 48) | ((UInt64)buffer[j + 2] << 40) | ((UInt64)buffer[j + 3] << 32) | 
                       ((UInt64)buffer[j + 4] << 24) | ((UInt64)buffer[j + 5] << 16) | ((UInt64)buffer[j + 6] <<  8) | ((UInt64)buffer[j + 7]);
            for (int t = 16; t < 80; ++t)
                W[t] = Wsigma1(W[t - 2]) + W[t - 7] + Wsigma0(W[t - 15]) + W[t - 16];

            Sha512State state = (Sha512State)hashState;
            // Init working variables
            UInt64 a = state.H[0];
            UInt64 b = state.H[1];
            UInt64 c = state.H[2];
            UInt64 d = state.H[3];
            UInt64 e = state.H[4];
            UInt64 f = state.H[5];
            UInt64 g = state.H[6];
            UInt64 h = state.H[7];

            // 80 rounds
            for (int r = 0; r < 80; ++r)
            {
                UInt64 T1 = h + Sigma1(e) + Choice(e, f, g) + K[r] + W[r];
                UInt64 T2 = Sigma0(a) + Majority(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + T1;
                d = c;
                c = b;
                b = a;
                a = T1 + T2;
            }

            // Update hash state
            state.H[0] += a;
            state.H[1] += b;
            state.H[2] += c;
            state.H[3] += d;
            state.H[4] += e;
            state.H[5] += f;
            state.H[6] += g;
            state.H[7] += h;
        }

        protected override byte[] FinalHash(ISha2State hashState)
        {
            var size = 8;
            if (this._bitLen == 384) size = 6;
            byte[] result = new byte[size * 8];

            Sha512State state = (Sha512State)hashState;
            for (int h = 0, p = 0; h < size; h++, p += 8)
            {
                var hState = state.H[h];
                result[p + 0] = (byte)(hState >> 56);
                result[p + 1] = (byte)(hState >> 48);
                result[p + 2] = (byte)(hState >> 40);
                result[p + 3] = (byte)(hState >> 32);
                result[p + 4] = (byte)(hState >> 24);
                result[p + 5] = (byte)(hState >> 16);
                result[p + 6] = (byte)(hState >> 8);
                result[p + 7] = (byte)(hState);
            }

            return result;
        }

        private static UInt64 Choice(UInt64 x, UInt64 y, UInt64 z)
        {
            return (x & y) ^ ((~x) & z);
        }

        private static UInt64 Majority(UInt64 x, UInt64 y, UInt64 z)
        {
            return (x & y) ^ (x & z) ^ (y & z);
        }

        private static UInt64 Sigma0(UInt64 x)
        {
            return ((x >> 28) | (x << 36)) ^ ((x >> 34) | (x << 30)) ^ ((x >> 39) | (x << 25));
        }

        private static UInt64 Sigma1(UInt64 x)
        {
            return ((x >> 14) | (x << 50)) ^ ((x >> 18) | (x << 46)) ^ ((x >> 41) | (x << 23));
        }

        private static UInt64 Wsigma0(UInt64 x)
        {
            return ((x >> 1) | (x << 63)) ^ ((x >> 8) | (x << 56)) ^ (x >> 7);
        }

        private static UInt64 Wsigma1(UInt64 x)
        {
            return ((x >> 19) | (x << 45)) ^ ((x >> 61) | (x << 3)) ^ (x >> 6);
        }
    }

    /// <summary>
    /// HashAlgorithm implementation for Sha2 
    /// </summary>
    public class Sha2HashAlgorithm : HashAlgorithm
    {
        private int _bitLen;
        private Sha2 _sha2;
        private byte[] _finalHash;
        private MemoryStream _stream;

        private Sha2HashAlgorithm(int bitLen)
        {
            this._bitLen = bitLen;
            this._sha2 = Sha2.Create(bitLen);
            this._finalHash = null;
            this._stream = new MemoryStream();
        }

        public static Sha2HashAlgorithm Create(int bitLen)
        {
            return new Sha2HashAlgorithm(bitLen);
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            this._stream.Write(array, ibStart, cbSize);
        }

        protected override byte[] HashFinal()
        {
            this._stream.Seek(0, SeekOrigin.Begin);
            this._finalHash = this._sha2.Compute(new StreamToHashReader(this._stream));
            return this._finalHash;
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (this._stream != null)
                this._stream.Dispose();
            this._stream = null;
        }

        public override bool CanTransformMultipleBlocks => true;

        public override byte[] Hash => this._finalHash;

        public override int HashSize => this._bitLen;

        public override void Initialize()
        {
            this._finalHash = null;
            if (this._stream != null)
                this._stream.Dispose();
            this._stream = new MemoryStream();
        }

        public override string ToString()
        {
            if (this._finalHash != null)
                return String.Format("Sha2 {0}: {1}", this.HashSize, String.Join("", this._finalHash.Select(b => b.ToString("X2"))));
            else
                return String.Format("Sha2 {0}", this.HashSize);
        }
    }
}