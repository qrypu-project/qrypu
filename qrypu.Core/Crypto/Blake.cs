/*
 * (C) 2018 José Hurtado
 * 
 * ES: Implementación del algoritmo Blake, finalista del concurso NIST para SHA3
 * Se limita a mensajes de bytes enteros y está preparado para procesar streams
 * Este código está probado con los mensajes propuestos por NIST y los resultados 
 * entregados por el equipo desarrollador del algoritmo.
 * 
 * Licencia: para este archivo se aplica: https://opensource.org/licenses/MIT
 */
namespace qrypu.Core.Crypto
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;

    /// <summary>
    /// Blake Hash implementation based on its 64 bit optimized version
    /// <see cref="https://131002.net/blake"/>
    /// </summary>
    public abstract class Blake : ICryptoHash
    {
        /// <summary>
        /// Permut table for Blake
        /// </summary>
        protected UInt32[][] PERMUT_TABLE = new UInt32[][] {
            new UInt32[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
            new UInt32[] {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
            new UInt32[] {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
            new UInt32[] {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
            new UInt32[] {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
            new UInt32[] {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
            new UInt32[] {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
            new UInt32[] {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
            new UInt32[] {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
            new UInt32[] {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
        };

        /// <summary>
        /// Creates a new instance of Blake hasher configured for the result bit length specified
        /// </summary>
        /// <param name="bitLen">Bits for result: 224, 256, 384 or 512</param>
        /// <returns>Hasher instance</returns>
        public static Blake Create(int bitLen)
        {
            if ((bitLen != 224) && (bitLen != 256) && (bitLen != 384) && (bitLen != 512))
                throw new ArgumentException();

            Blake result;
            if (bitLen == 256 || bitLen == 224)
                result = new Blake256();
            else
                result = new Blake512();

            result.Config(bitLen);
            return result;
        }

        /// <summary>
        /// Internal variables are set by Config method.
        /// An instance can Compute multiple hashes while result bit len not change.
        /// </summary>
        private int _bufferLength = 0;
        private byte _finalXor = 0;

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
            this._finalXor = (byte)((((bitLen >> 7) & 0x01) == 1) ? 0 : 1);
            this._bitLen = bitLen;
        }

        /// <summary>
        /// Initialize instance for hash computing
        /// </summary>
        /// <param name="hashState">Hash State initialized</param>
        protected abstract void InitState(out IBlakeState hashState);

        /// <summary>
        /// Call hash Compress function with partial data
        /// </summary>
        /// <param name="hashState">Current hash state</param>
        /// <param name="buffer">New buffer to compress</param>
        /// <param name="bitCount">Current bit count</param>
        protected abstract void Compress(IBlakeState hashState, byte[] buffer, UInt64 bitCount);

        /// <summary>
        /// Process final state to hash format
        /// </summary>
        /// <param name="hashState">Final hash state</param>
        /// <returns>Hash computed</returns>
        protected abstract byte[] FinalHash(IBlakeState hashState);

        /// <summary>
        /// Compute hash from message source
        /// </summary>
        /// <param name="source">Stream or buffer</param>
        /// <returns>Hash computed</returns>
        public byte[] Compute(MessageToHashReader source)
        {
            // INIT
            // Init hash variables (in derivate class)
            var bufferLength = this._bufferLength;
            InitState(out IBlakeState hashState);

            // UPDATE
            // Transform complete blocks
            byte[] buffer = new byte[bufferLength];
            UInt64 bitLength = 0;
            UInt64 blockCount = 0;
            int bytesRead;
            while ((bytesRead = source.Read(buffer, 0, bufferLength)) == bufferLength)
            {
                bitLength += (UInt64)(bytesRead << 3);
                Compress(hashState, buffer, bitLength);
                blockCount++;
            }
            bitLength += (UInt64)(bytesRead << 3);

            // FINAL
            // Calc extra blocks
            int bitWrap = bufferLength << 3;
            //int finalBytes = bufferLength >> 3;
            UInt64 bitPadding = (UInt64)((((-(long)bitLength - (bufferLength + 1)) % bitWrap) + bitWrap) % bitWrap);
            UInt64 totalBlocks = (bitLength + bitPadding + ((UInt64)bufferLength + 1)) / (UInt64)bitWrap;
            int blocksLeft = (int)(totalBlocks - blockCount);

            // 0x80 tail and zero padding
            buffer[bytesRead] = 0x80;
            for (int p = bytesRead + 1; p < bufferLength; p++)
                buffer[p] = 0x00;

            // Process extra blocks

            if (blocksLeft > 1) // if two extra blocks
            {
                Compress(hashState, buffer, bitLength);
                buffer = new byte[bufferLength];
            }
            // last extra block
            {
                byte[] length = BitConverter.GetBytes((UInt64)bitLength);
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(length);
                Buffer.BlockCopy(length, 0, buffer, bufferLength - 8, 8);
                buffer[bufferLength - (bufferLength >> 3) - 1] ^= this._finalXor;
                if (blocksLeft == 2 || (blocksLeft == 1 && bytesRead == 0))
                    bitLength = 0;
                Compress(hashState, buffer, bitLength);
            }

            // Finalize hash and truncate (Output Transformation)
            return FinalHash(hashState);
        }

        protected interface IBlakeState { };
    }

    /// <summary>
    /// Blake for 224 and 256 bit length hash result
    /// </summary>
    internal class Blake256 : Blake
    {
        private static readonly UInt32[] _init224 = new UInt32[] {
            0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
        };

        private static readonly UInt32[] _init256 = new UInt32[] {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };

        private static readonly UInt32[] _const = new UInt32[] {
            0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
            0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c, 0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917
        };

        private const int ROUNDS = 14;

        private class Blake256State : IBlakeState
        {
            public UInt32[] H; // hash
            public UInt32[] B; // block
            public UInt32[] S; // salt
            public UInt32[] C; // counter
        }

        protected override void InitState(out IBlakeState hashState)
        {
            var result = new Blake256State()
            {
                B = new UInt32[16],
                S = new UInt32[4] { 0, 0, 0, 0 },
                H = new UInt32[8]
            };
            if (this._bitLen == 224)
                Array.Copy(_init224, result.H, 8);
            else
                Array.Copy(_init256, result.H, 8);
            hashState = result;
        }

        protected override void Compress(IBlakeState hashState, byte[] buffer, UInt64 bitCount)
        {
            var state = (Blake256State)hashState;
            state.B = Split(buffer);
            state.C = SplitCounter(bitCount);
            Compress(state.H, state.B, state.S, state.C);
        }

        protected override byte[] FinalHash(IBlakeState hashState)
        {
            var state = (Blake256State)hashState;
            var result = Join(state.H);
            if (this._bitLen == 224)
                Array.Resize(ref result, 28);
            return result;
        }

        private void Compress(UInt32[] hash, UInt32[] block, UInt32[] salt, UInt32[] counter)
        {
            UInt32[] state = new UInt32[] {
                hash[0], hash[1], hash[2], hash[3],
                hash[4], hash[5], hash[6], hash[7],
                salt[0] ^ _const[0], salt[1] ^ _const[1], salt[2] ^ _const[2], salt[3] ^ _const[3],
                counter[0] ^ _const[4], counter[0] ^ _const[5], counter[1] ^ _const[6], counter[1] ^ _const[7],
            };
            for (int round = 0; round < ROUNDS; round++)
            {
                Round(0, ref state[0], ref state[4], ref state[8], ref state[12], block, round);
                Round(1, ref state[1], ref state[5], ref state[9], ref state[13], block, round);
                Round(2, ref state[2], ref state[6], ref state[10], ref state[14], block, round);
                Round(3, ref state[3], ref state[7], ref state[11], ref state[15], block, round);

                Round(4, ref state[0], ref state[5], ref state[10], ref state[15], block, round);
                Round(5, ref state[1], ref state[6], ref state[11], ref state[12], block, round);
                Round(6, ref state[2], ref state[7], ref state[8], ref state[13], block, round);
                Round(7, ref state[3], ref state[4], ref state[9], ref state[14], block, round);
            }
            hash[0] = hash[0] ^ salt[0] ^ state[0] ^ state[8];
            hash[1] = hash[1] ^ salt[1] ^ state[1] ^ state[9];
            hash[2] = hash[2] ^ salt[2] ^ state[2] ^ state[10];
            hash[3] = hash[3] ^ salt[3] ^ state[3] ^ state[11];
            hash[4] = hash[4] ^ salt[0] ^ state[4] ^ state[12];
            hash[5] = hash[5] ^ salt[1] ^ state[5] ^ state[13];
            hash[6] = hash[6] ^ salt[2] ^ state[6] ^ state[14];
            hash[7] = hash[7] ^ salt[3] ^ state[7] ^ state[15];
        }

        private void Round(int i, ref UInt32 a, ref UInt32 b, ref UInt32 c, ref UInt32 d, UInt32[] block, int round)
        {
            round = round % 10;
            a = a + b + (block[PERMUT_TABLE[round][2 * i]] ^ _const[PERMUT_TABLE[round][2 * i + 1]]);
            d = (d ^ a) >> 16 | (d ^ a) << 16;
            c = c + d;
            b = (b ^ c) >> 12 | (b ^ c) << 20;
            a = a + b + (block[PERMUT_TABLE[round][2 * i + 1]] ^ _const[PERMUT_TABLE[round][2 * i]]);
            d = (d ^ a) >> 8 | (d ^ a) << 24;
            c = c + d;
            b = (b ^ c) >> 7 | (b ^ c) << 25;
        }

        private UInt32[] Split(byte[] data)
        {
            int parts = data.Length / 4;
            UInt32[] result = new UInt32[parts];
            byte[] item = new byte[4];
            for (int p = 0; p < parts; p++)
            {
                Array.Copy(data, p << 2, item, 0, 4);
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(item);
                result[p] = BitConverter.ToUInt32(item, 0);
            }
            return result;
        }

        private byte[] Join(UInt32[] data)
        {
            byte[] result = new byte[32];
            byte[] item = new byte[4];
            for (int i = 0, p = 0; i < data.Length; i++, p += 4)
            {
                item = BitConverter.GetBytes(data[i]);
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(item);
                result[p + 0] = item[0];
                result[p + 1] = item[1];
                result[p + 2] = item[2];
                result[p + 3] = item[3];
            }
            return result;
        }

        private UInt32[] SplitCounter(UInt64 bitCount)
        {
            var result = new UInt32[2];
            result[0] = (UInt32)((bitCount << 32) >> 32);
            result[1] = (UInt32)(bitCount >> 32);
            return result;
        }
    }

    /// <summary>
    /// Blake for 386 and 512 bit length hash result
    /// </summary>
    internal class Blake512 : Blake
    {
        private static readonly UInt64[] _init384 = new UInt64[] {
            0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
            0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
        };

        private static readonly UInt64[] _init512 = new UInt64[] {
            0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
            0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
        };

        private static readonly UInt64[] _const = new UInt64[] {
            0x243f6a8885a308d3, 0x13198a2e03707344, 0xa4093822299f31d0, 0x082efa98ec4e6c89,
            0x452821e638d01377, 0xbe5466cf34e90c6c, 0xc0ac29b7c97c50dd, 0x3f84d5b5b5470917,
            0x9216d5d98979fb1b, 0xd1310ba698dfb5ac, 0x2ffd72dbd01adfb7, 0xb8e1afed6a267e96,
            0xba7c9045f12c7f99, 0x24a19947b3916cf7, 0x0801f2e2858efc16, 0x636920d871574e69
        };

        private const int ROUNDS = 16;

        private class Blake512State : IBlakeState
        {
            public UInt64[] H;
            public UInt64[] B;
            public UInt64[] S;
        }

        protected override void InitState(out IBlakeState hashState)
        {
            var result = new Blake512State()
            {
                B = new UInt64[16],
                S = new UInt64[4] { 0, 0, 0, 0 },
                H = new UInt64[8]
            };
            if (this._bitLen == 384)
                Array.Copy(_init384, result.H, 8);
            else
                Array.Copy(_init512, result.H, 8);
            hashState = result;
        }

        protected override void Compress(IBlakeState hashState, byte[] buffer, UInt64 bitCount)
        {
            var state = (Blake512State)hashState;
            state.B = Split(buffer);
            Compress(state.H, state.B, state.S, new UInt64[] { bitCount, 0x0 });
        }

        protected override byte[] FinalHash(IBlakeState hashState)
        {
            var state = (Blake512State)hashState;
            var result = Join(state.H);
            if (this._bitLen == 384)
                Array.Resize(ref result, 48);
            return result;
        }

        private void Compress(UInt64[] hash, UInt64[] block, UInt64[] salt, UInt64[] counter)
        {
            UInt64[] state = new UInt64[] {
                hash[0], hash[1], hash[2], hash[3],
                hash[4], hash[5], hash[6], hash[7],
                salt[0] ^ _const[0], salt[1] ^ _const[1], salt[2] ^ _const[2], salt[3] ^ _const[3],
                counter[0] ^ _const[4], counter[0] ^ _const[5], counter[1] ^ _const[6], counter[1] ^ _const[7],
            };
            for (int round = 0; round < ROUNDS; round++)
            {
                Round(0, ref state[0], ref state[4], ref state[8], ref state[12], block, round);
                Round(1, ref state[1], ref state[5], ref state[9], ref state[13], block, round);
                Round(2, ref state[2], ref state[6], ref state[10], ref state[14], block, round);
                Round(3, ref state[3], ref state[7], ref state[11], ref state[15], block, round);

                Round(4, ref state[0], ref state[5], ref state[10], ref state[15], block, round);
                Round(5, ref state[1], ref state[6], ref state[11], ref state[12], block, round);
                Round(6, ref state[2], ref state[7], ref state[8], ref state[13], block, round);
                Round(7, ref state[3], ref state[4], ref state[9], ref state[14], block, round);
            }
            hash[0] = hash[0] ^ salt[0] ^ state[0] ^ state[8];
            hash[1] = hash[1] ^ salt[1] ^ state[1] ^ state[9];
            hash[2] = hash[2] ^ salt[2] ^ state[2] ^ state[10];
            hash[3] = hash[3] ^ salt[3] ^ state[3] ^ state[11];
            hash[4] = hash[4] ^ salt[0] ^ state[4] ^ state[12];
            hash[5] = hash[5] ^ salt[1] ^ state[5] ^ state[13];
            hash[6] = hash[6] ^ salt[2] ^ state[6] ^ state[14];
            hash[7] = hash[7] ^ salt[3] ^ state[7] ^ state[15];
        }

        private void Round(int i, ref UInt64 a, ref UInt64 b, ref UInt64 c, ref UInt64 d, UInt64[] block, int round)
        {
            round = round % 10;
            a = a + b + (block[PERMUT_TABLE[round][2 * i]] ^ _const[PERMUT_TABLE[round][2 * i + 1]]);
            d = (d ^ a) >> 32 | (d ^ a) << 32;
            c = c + d;
            b = (b ^ c) >> 25 | (b ^ c) << 39;
            a = a + b + (block[PERMUT_TABLE[round][2 * i + 1]] ^ _const[PERMUT_TABLE[round][2 * i]]);
            d = (d ^ a) >> 16 | (d ^ a) << 48;
            c = c + d;
            b = (b ^ c) >> 11 | (b ^ c) << 53;
        }

        private UInt64[] Split(byte[] data)
        {
            int parts = data.Length / 8;
            UInt64[] result = new UInt64[parts];
            byte[] item = new byte[8];
            for (int p = 0; p < parts; p++)
            {
                Array.Copy(data, p << 3, item, 0, 8);
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(item);
                result[p] = BitConverter.ToUInt64(item, 0);
            }
            return result;
        }

        private byte[] Join(UInt64[] data)
        {
            byte[] result = new byte[64];
            byte[] item = new byte[8];
            for (int i = 0; i < data.Length; i++)
            {
                item = BitConverter.GetBytes(data[i]);
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(item);
                Buffer.BlockCopy(item, 0, result, i << 3, 8);
            }
            return result;
        }
    }

    /// <summary>
    /// HashAlgorithm implementation for Blake 
    /// </summary>
    public class BlakeHashAlgorithm : HashAlgorithm
    {
        private int _bitLen;
        private Blake _blake;
        private byte[] _finalHash;
        private MemoryStream _stream;

        private BlakeHashAlgorithm(int bitLen)
        {
            this._bitLen = bitLen;
            this._blake = Blake.Create(bitLen);
            this._finalHash = null;
            this._stream = new MemoryStream();
        }

        public static BlakeHashAlgorithm Create(int bitLen)
        {
            return new BlakeHashAlgorithm(bitLen);
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            this._stream.Write(array, ibStart, cbSize);
        }

        protected override byte[] HashFinal()
        {
            this._stream.Seek(0, SeekOrigin.Begin);
            this._finalHash = this._blake.Compute(new StreamToHashReader(this._stream));
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
                return String.Format("Blake {0}: {1}", this.HashSize, String.Join("", this._finalHash.Select(b => b.ToString("X2"))));
            else
                return String.Format("Blake {0}", this.HashSize);
        }
    }
}