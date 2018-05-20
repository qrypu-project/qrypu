/*
 * (C) 2018 José Hurtado
 * 
 * ES: Implementación parcial del algoritmo Skein, finalista del concurso NIST para SHA3
 * Skein tiene más funcionalidades que el hash de mensajes, pero esta implementación está
 * limitado a esta función y para  mensajes de bytes enteros, está preparado para procesar streams
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

    public abstract class Skein : ICryptoHash
    {
        /// <summary>
        /// Creates a new instance of Skein hasher configured for the result bit length specified
        /// </summary>
        /// <param name="bitLen">Bits for result: 224, 256, 384 or 512</param>
        /// <returns>Hasher instance</returns>
        public static Skein Create(int bitLen)
        {
            if ((bitLen != 224) && (bitLen != 256) && (bitLen != 384) && (bitLen != 512))
                throw new ArgumentException();

            Skein result;
            if (bitLen == 256 || bitLen == 224)
                result = new Skein256();
            else
                result = new Skein512();

            result.Config(bitLen);
            return result;
        }

        protected enum BlockType : byte
        {
            //KEY   =   0,  /* key, for MAC and KDF */
            //CFG   =   4,  /* configuration block */
            //PERS  =   8,  /* personalization string */
            //PK    =  12,  /* public key (for digital signature hashing) */
            //KDF   =  16,  /* key identifier for KDF */
            //NONCE =  20,  /* nonce for PRNG */
            MSG   =  48,  /* message processing */
            OUT   =  63,  /* output stage */
            //MASK  =  63   /* bit field mask */
        }

        [Flags]
        protected enum SkeinFlags : UInt64
        {
            None      = 0x0000000000000000,
            //TreeLevel = 0x007F000000000000,  // 0000 0000 01111 11111 ...
            //BitPad    = 0x0080000000000000,  // 0000 0000 10000 00000 ...
            //BlockType = 0x3F00000000000000,  // 0011 1111 00000 00000 ...
            First     = 0x4000000000000000,  // 0100 0000 00000 00000 ...
            Final     = 0x8000000000000000   // 1000 0000 00000 00000 ...
        }

        protected struct SkeinState
        {
            public UInt64[] Hash;
            public SkeinFlags Flags;
        }

        /// <summary>
        /// Internal variables are set by Config method.
        /// An instance can Compute multiple hashes while result bit len not change.
        /// </summary>
        protected int _stateWords;
        protected int _bufferLength;
        protected UInt64[] _initState;

        /// <summary>
        /// Number of bits in hash result
        /// </summary>
        protected int _bitLen;
        public int BitLen => _bitLen;

        protected SkeinFlags SetType(BlockType type, SkeinFlags extraFlag = SkeinFlags.None)
        {
            return (SkeinFlags)((UInt64)type << 56)
                | SkeinFlags.First
                | extraFlag;
        }

        /// <summary>
        /// Call to set result bit len and internal mode of operation
        /// </summary>
        /// <param name="bitLen">Bit len 224, 256, 384 and 512</param>
        public void Config(int bitLen)
        {
            if ((bitLen != 224) && (bitLen != 256) && (bitLen != 384) && (bitLen != 512))
                throw new ArgumentException();
            this._bitLen = bitLen;
            InitMode();
        }

        protected abstract void InitMode();
        protected abstract void Compress(ref SkeinState State, byte[] buffer, UInt64 bitCount);

        /// <summary>
        /// Compute hash from message source
        /// </summary>
        /// <param name="source">Stream or buffer</param>
        /// <returns>Hash computed</returns>
        public byte[] Compute(MessageToHashReader source)
        {
            // INIT
            // Init hash buffer
            var state = Init();
            var bufferLength = this._bufferLength;
            var remain = source.Length; // Skein needs to know data length

            // UPDATE
            // Transform complete blocks
            byte[] buffer = new byte[bufferLength];
            long allBytesRead = 0;
            int bytesRead;
            while (((bytesRead = source.Read(buffer, 0, bufferLength)) == bufferLength)
                && ((remain -= bytesRead) > 0)) // This condition order enable full final block
            {
                allBytesRead += bytesRead;
                Compress(ref state, buffer, (UInt64)allBytesRead);
            }
            allBytesRead += bytesRead;

            // FINAL
            // Process last block with data
            state.Flags |= SkeinFlags.Final;
            for (int p = bytesRead; p < bufferLength; p++)  // fill with 0 rest of buffer
                buffer[p] = 0x00;
            Compress(ref state, buffer, (ulong)allBytesRead);

            // Last block for extended hash (> buffer length)
            state.Flags = SetType(BlockType.OUT, SkeinFlags.Final);
            buffer = new byte[bufferLength];
            Compress(ref state, buffer, 8);

            // Format final hash
            return FinalHash(state);
        }

        private SkeinState Init()
        {
            var result = new SkeinState();
            result.Hash = new UInt64[this._stateWords];
            for (int h = 0; h < this._stateWords; h++)
            {
                result.Hash[h] = this._initState[h];
            }
            result.Flags = SetType(BlockType.MSG);
            return result;
        }

        protected abstract byte[] FinalHash(SkeinState state);

        protected UInt64[] ToBlock(byte[] buffer)
        {
            var bufferLength = this._bufferLength;
            var count = this._stateWords;

            var block = new UInt64[count];
            #if !BIGENDIAN
            for (int b = 0; b < count; b++)
            {
                block[b] = BitConverter.ToUInt64(buffer, b << 3);
            }
            #else
            var leBuffer = new byte[bufferLength];
            Buffer.BlockCopy(buffer, 0, leBuffer, 0, bufferLength);
            Array.Reverse(leBuffer);
            for (int i = count - 1, b = 0; i >= 0; i--, b++)
            {
                block[b] = BitConverter.ToUInt64(leBuffer, i << 3);
            }
            #endif
            return block;
        }
    }

    /// <summary>
    /// Skein for 224 and 256 bit length hash result
    /// </summary>
    internal class Skein256 : Skein
    {
        private static readonly UInt64[] SKEIN_256_IV_224 =
        {
            0xB80929699AE0F431,
            0xD340DC14A06929DC,
            0xAE866594BDE4DC5A,
            0x339767C25A60EA1D
        };

        private static readonly UInt64[] SKEIN_256_IV_256 =
        {
            0x388512680E660046,
            0x4B72D5DEC5A8FF01,
            0x281A9298CA5EB3A5,
            0x54CA5249F46070C4
        };

        private const int SKEIN_256_STATE_WORDS = 4;
        private const int SKEIN_256_BLOCK_BYTES = 8 * SKEIN_256_STATE_WORDS;

        protected override void InitMode()
        {
            this._stateWords = SKEIN_256_STATE_WORDS;
            switch (this._bitLen)
            {
                case 224:
                    this._initState = SKEIN_256_IV_224;
                    break;
                case 256:
                    this._initState = SKEIN_256_IV_256;
                    break;
            }
            this._bufferLength = SKEIN_256_BLOCK_BYTES;
        }

        protected override void Compress(ref SkeinState state, byte[] buffer, UInt64 bitCount)
        {
            var keyState = new UInt64[SKEIN_256_STATE_WORDS + 1];
            var tweakState = new UInt64[3];
            tweakState[0] = bitCount;
            tweakState[1] = (UInt64)state.Flags;

            keyState[0] = state.Hash[0];
            keyState[1] = state.Hash[1];
            keyState[2] = state.Hash[2];
            keyState[3] = state.Hash[3];
            keyState[4] = keyState[0] ^ keyState[1] ^ keyState[2] ^ keyState[3] ^ 0x5555555555555555;

            tweakState[2] = tweakState[0] ^ tweakState[1];

            var block = ToBlock(buffer);
            var X = new UInt64[SKEIN_256_STATE_WORDS];
            for (int i = 0; i < SKEIN_256_STATE_WORDS; i++)
                X[i] = block[i];

            X[0] = block[0] + keyState[0];
            X[1] = block[1] + keyState[1] + tweakState[0];
            X[2] = block[2] + keyState[2] + tweakState[1];
            X[3] = block[3] + keyState[3];

            // 72 round plus injects
            EigthRounds(X, keyState, tweakState, 0);
            EigthRounds(X, keyState, tweakState, 1);
            EigthRounds(X, keyState, tweakState, 2);
            EigthRounds(X, keyState, tweakState, 3);
            EigthRounds(X, keyState, tweakState, 4);
            EigthRounds(X, keyState, tweakState, 5);
            EigthRounds(X, keyState, tweakState, 6);
            EigthRounds(X, keyState, tweakState, 7);
            EigthRounds(X, keyState, tweakState, 8);

            state.Hash[0] = X[0] ^ block[0];
            state.Hash[1] = X[1] ^ block[1];
            state.Hash[2] = X[2] ^ block[2];
            state.Hash[3] = X[3] ^ block[3];

            state.Flags &= ~SkeinFlags.First; // Disable "First" flag
        }

        private void EigthRounds(UInt64[] X, UInt64[] keyState, UInt64[] tweakState, int roundGroup)
        {
            Round(X, 0, 1, 2, 3, 0);
            Round(X, 0, 3, 2, 1, 1);
            Round(X, 0, 1, 2, 3, 2);
            Round(X, 0, 3, 2, 1, 3);
            Inject(X, keyState, tweakState, 2 * roundGroup);
            Round(X, 0, 1, 2, 3, 4);
            Round(X, 0, 3, 2, 1, 5);
            Round(X, 0, 1, 2, 3, 6);
            Round(X, 0, 3, 2, 1, 7);
            Inject(X, keyState, tweakState, (2 * roundGroup) + 1);
        }

        private void Inject(UInt64[] X, UInt64[] keyState, UInt64[] tweakState, int roundGroup)
        {
            X[0] += keyState[(roundGroup + 1) % 5];
            X[1] += keyState[(roundGroup + 2) % 5] + tweakState[(roundGroup + 1) % 3];
            X[2] += keyState[(roundGroup + 3) % 5] + tweakState[(roundGroup + 2) % 3];
            X[3] += keyState[(roundGroup + 4) % 5] + (UInt64)(roundGroup + 1);
        }

        private static readonly int[,] R_256 =
            { { 5, 56 }, { 36, 28 }, { 13, 46 }, { 58, 44 }, { 26, 20 }, { 53, 35 }, { 11, 42 }, { 59, 50 } };

        private void Round(UInt64[] X, int p0, int p1, int p2, int p3, int rotator)
        {
            X[p0] += X[p1];
            X[p1] = (X[p1] << R_256[rotator, 0]) | (X[p1] >> (64 - R_256[rotator, 0]));
            X[p1] ^= X[p0];

            X[p2] += X[p3];
            X[p3] = (X[p3] << R_256[rotator, 1]) | (X[p3] >> (64 - R_256[rotator, 1]));
            X[p3] ^= X[p2];
        }

        protected override byte[] FinalHash(SkeinState state)
        {
            var hashBytes = SKEIN_256_BLOCK_BYTES;
            var lastBytes = 8;
            if (this._bitLen == 224)
            {
                hashBytes -= 4;
                lastBytes = 4;
            }

            var result = new byte[hashBytes];
            int h;
            for (h = 0; h < SKEIN_256_STATE_WORDS - 1; h++)
            {
                var completeBytes = BitConverter.GetBytes(state.Hash[h]);
                Buffer.BlockCopy(completeBytes, 0, result, h << 3, 8);
            }
            var finalBytes = BitConverter.GetBytes(state.Hash[h]);
            Buffer.BlockCopy(finalBytes, 0, result, h << 3, lastBytes);

            return result;
        }
    }

    /// <summary>
    /// Skein for 386 and 512 bit length hash result
    /// </summary>
    internal class Skein512 : Skein
    {
        private static readonly UInt64[] SKEIN_512_IV_384 =
        {
            0xE5BF4D02BA62494C,
            0x7AA1EABCC3E6FC68,
            0xBBE5FC26E1038C5A,
            0x53C9903E8F88E9FA,
            0xF30D8DDDFB940C83,
            0x500FDA3C4865ABEC,
            0x2226C67F745BC5E7,
            0x015DA80077C639F7
        };

        private static readonly UInt64[] SKEIN_512_IV_512 =
        {
            0xA8D47980544A6E32,
            0x847511533E9B1A8A,
            0x6FAEE870D8E81A00,
            0x58B0D9D6CB557F92,
            0x9BBC0051DAC1D4E9,
            0xB744E2B1D189E7CA,
            0x979350FA709C5EF3,
            0x0350125A92067BCD
        };

        private const int SKEIN_512_STATE_WORDS = 8;
        private const int SKEIN_512_BLOCK_BYTES = 8 * SKEIN_512_STATE_WORDS;

        protected override void InitMode()
        {
            this._stateWords = SKEIN_512_STATE_WORDS;
            switch (this._bitLen)
            {
                case 384:
                    this._initState = SKEIN_512_IV_384;
                    break;
                case 512:
                    this._initState = SKEIN_512_IV_512;
                    break;
            }
            this._bufferLength = SKEIN_512_BLOCK_BYTES;
        }

        protected override void Compress(ref SkeinState state, byte[] buffer, UInt64 bitCount)
        {
            var keyState = new UInt64[SKEIN_512_STATE_WORDS + 1];
            var tweakState = new UInt64[3];
            tweakState[0] = bitCount;
            tweakState[1] = (UInt64)state.Flags;

            keyState[0] = state.Hash[0];
            keyState[1] = state.Hash[1];
            keyState[2] = state.Hash[2];
            keyState[3] = state.Hash[3];
            keyState[4] = state.Hash[4];
            keyState[5] = state.Hash[5];
            keyState[6] = state.Hash[6];
            keyState[7] = state.Hash[7];
            keyState[8] = keyState[0] ^ keyState[1] ^ keyState[2] ^ keyState[3] ^
                          keyState[4] ^ keyState[5] ^ keyState[6] ^ keyState[7] ^ 0x5555555555555555;

            tweakState[2] = tweakState[0] ^ tweakState[1];

            var block = ToBlock(buffer);
            var X = new UInt64[SKEIN_512_STATE_WORDS];
            for (int i = 0; i < SKEIN_512_STATE_WORDS; i++)
                X[i] = block[i];

            X[0] = block[0] + keyState[0];
            X[1] = block[1] + keyState[1];
            X[2] = block[2] + keyState[2];
            X[3] = block[3] + keyState[3];
            X[4] = block[4] + keyState[4];
            X[5] = block[5] + keyState[5] + tweakState[0];
            X[6] = block[6] + keyState[6] + tweakState[1];
            X[7] = block[7] + keyState[7];

            // 72 round plus injects
            EigthRounds(X, keyState, tweakState, 0);
            EigthRounds(X, keyState, tweakState, 1);
            EigthRounds(X, keyState, tweakState, 2);
            EigthRounds(X, keyState, tweakState, 3);
            EigthRounds(X, keyState, tweakState, 4);
            EigthRounds(X, keyState, tweakState, 5);
            EigthRounds(X, keyState, tweakState, 6);
            EigthRounds(X, keyState, tweakState, 7);
            EigthRounds(X, keyState, tweakState, 8);

            state.Hash[0] = X[0] ^ block[0];
            state.Hash[1] = X[1] ^ block[1];
            state.Hash[2] = X[2] ^ block[2];
            state.Hash[3] = X[3] ^ block[3];
            state.Hash[4] = X[4] ^ block[4];
            state.Hash[5] = X[5] ^ block[5];
            state.Hash[6] = X[6] ^ block[6];
            state.Hash[7] = X[7] ^ block[7];

            state.Flags &= ~SkeinFlags.First; // Disable "First" flag
        }

        private void EigthRounds(UInt64[] X, UInt64[] keyState, UInt64[] tweakState, int roundGroup)
        {
            Round(X, 0, 1, 2, 3, 4, 5, 6, 7, 0);
            Round(X, 2, 1, 4, 7, 6, 5, 0, 3, 1);
            Round(X, 4, 1, 6, 3, 0, 5, 2, 7, 2);
            Round(X, 6, 1, 0, 7, 2, 5, 4, 3, 3);
            Inject(X, keyState, tweakState, 2 * roundGroup);
            Round(X, 0, 1, 2, 3, 4, 5, 6, 7, 4);
            Round(X, 2, 1, 4, 7, 6, 5, 0, 3, 5);
            Round(X, 4, 1, 6, 3, 0, 5, 2, 7, 6);
            Round(X, 6, 1, 0, 7, 2, 5, 4, 3, 7);
            Inject(X, keyState, tweakState, (2 * roundGroup) + 1);
        }

        private void Inject(UInt64[] X, UInt64[] keyState, UInt64[] tweakState, int roundGroup)
        {
            X[0] += keyState[(roundGroup + 1) % 9];
            X[1] += keyState[(roundGroup + 2) % 9];
            X[2] += keyState[(roundGroup + 3) % 9];
            X[3] += keyState[(roundGroup + 4) % 9];
            X[4] += keyState[(roundGroup + 5) % 9];
            X[5] += keyState[(roundGroup + 6) % 9] + tweakState[(roundGroup + 1) % 3];
            X[6] += keyState[(roundGroup + 7) % 9] + tweakState[(roundGroup + 2) % 3];
            X[7] += keyState[(roundGroup + 8) % 9] + (UInt64)(roundGroup + 1);
        }

        private static readonly int[,] R_512 =
        {
            { 38, 30, 50, 53 }, { 48, 20, 43, 31 }, { 34, 14, 15, 27 }, { 26, 12, 58,  7 },
            { 33, 49,  8, 42 }, { 39, 27, 41, 14 }, { 29, 26, 11,  9 }, { 33, 51, 39, 35 }
        };

        private void Round(UInt64[] X, int p0, int p1, int p2, int p3, int p4, int p5, int p6, int p7, int rotator)
        {
            X[p0] += X[p1];
            X[p1] = (X[p1] << R_512[rotator, 0]) | (X[p1] >> (64 - R_512[rotator, 0]));
            X[p1] ^= X[p0];

            X[p2] += X[p3];
            X[p3] = (X[p3] << R_512[rotator, 1]) | (X[p3] >> (64 - R_512[rotator, 1]));
            X[p3] ^= X[p2];

            X[p4] += X[p5];
            X[p5] = (X[p5] << R_512[rotator, 2]) | (X[p5] >> (64 - R_512[rotator, 2]));
            X[p5] ^= X[p4];

            X[p6] += X[p7];
            X[p7] = (X[p7] << R_512[rotator, 3]) | (X[p7] >> (64 - R_512[rotator, 3]));
            X[p7] ^= X[p6];
        }

        protected override byte[] FinalHash(SkeinState state)
        {
            var hashBytes = SKEIN_512_BLOCK_BYTES;
            if (this._bitLen == 384)
                hashBytes -= 16;

            var result = new byte[hashBytes];
            int hashCount = hashBytes / 8;
            for (int h = 0; h < hashCount; h++)
            {
                var bytes = BitConverter.GetBytes(state.Hash[h]);
                Buffer.BlockCopy(bytes, 0, result, h << 3, 8);
            }

            return result;
        }
    }

    /// <summary>
    /// HashAlgorithm implementation for Skein
    /// </summary>
    public class SkeinHashAlgorithm : HashAlgorithm
    {
        private int _bitLen;
        private Skein _skein;
        private byte[] _finalHash;
        private MemoryStream _stream;

        private SkeinHashAlgorithm(int bitLen)
        {
            this._bitLen = bitLen;
            this._skein = Skein.Create(bitLen);
            this._finalHash = null;
            this._stream = new MemoryStream();
        }

        public static SkeinHashAlgorithm Create(int bitLen)
        {
            return new SkeinHashAlgorithm(bitLen);
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            this._stream.Write(array, ibStart, cbSize);
        }

        protected override byte[] HashFinal()
        {
            this._stream.Seek(0, SeekOrigin.Begin);
            this._finalHash = this._skein.Compute(new StreamToHashReader(this._stream));
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
                return String.Format("Skein {0}: {1}", this.HashSize, String.Join("", this._finalHash.Select(b => b.ToString("X2"))));
            else
                return String.Format("Skein {0}", this.HashSize);
        }
    }
}