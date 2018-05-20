/*
 * (C) 2018 José Hurtado
 * 
 * Serie: Qrypu Modified Hash  (Qmh)
 * Qmh Name: Huk  (one, ES:uno, 1)
 * 
 * ES: Algoritmo de hash modificado a partir de SHA2, con las siguientes diferencias:
 * - En la inicialización de hash y W se utilizan los primos subsiguientes (419..827)
 * - Se rellena el último bloque incompleto con una representacion hexadecimal de la 
 *   parte decimal de Pi, y de ser necesario, se rellena el último bloque extra para 
 *   con Phi, antes de los valores a continuación
 * - En la parte final del último bloque se agregan dos bytes de hash bitLen en bigendian, 
 *   justo antes de la longitud del mensaje en bits (que son 64 bits para 254 y 512)
 * - Se cambia la estructura de las rondas de compresión, que a su vez son menos
 *   56 para 224/256 y 64 para 384/512
 * - Las cuatro funciones Sigma tienen otro desplazamiento
 * - Se actiliza el estado del hash con XOR en lugar de +
 * En la capeta qrypu.Core.Test.NetCore/Crypto/QmhHuk_Avalanche se muestran los bitmap
 * de las pruebas de avalancha con resultados similares a Sha2, tal como se esperaba.
 * 
 * Licencia: TEMPORAL y ABREVIADA para este archivo es: Código Abierto para revisión.
 *   Sólo se permite el uso dentro del proyecto qrypu.
 */
namespace qrypu.Core.Crypto
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;

    public abstract class QmhHuk : ICryptoHash
    {
        public static QmhHuk Create(int bitLen)
        {
            if ((bitLen != 224) && (bitLen != 256) && (bitLen != 384) && (bitLen != 512))
                throw new ArgumentException();

            QmhHuk result;
            if (bitLen == 256 || bitLen == 224)
                result = new QmhHuk256();
            else
                result = new QmhHuk512();

            result.Config(bitLen);
            return result;
        }

        private int _bufferLength = 0;
        private byte[] _bitLenMark = new byte[] { 0x00, 0x00 };

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
            this._bitLenMark[0] = (byte)(bitLen >> 8);
            this._bitLenMark[1] = (byte)(bitLen & 0xFF);
            this._bitLen = bitLen;
        }

        /// <summary>
        /// Initialize Hash State
        /// </summary>
        /// <param name="hashState">Hash State initialized</param>
        protected abstract void InitState(out IQmhHukState hashState);

        /// <summary>
        /// Compress data from buffer
        /// </summary>
        /// <param name="hashState"></param>
        /// <param name="buffer"></param>
        protected abstract void Compress(IQmhHukState hashState, byte[] buffer);

        protected abstract byte[] FinalHash(IQmhHukState hashState);

        private static readonly byte[] PI_PADDING = new byte[]
        { 0x24, 0x3F, 0x6A, 0x88, 0x85, 0xA3, 0x08, 0xD3, 0x13, 0x19, 0x8A, 0x2E, 0x03, 0x70, 0x73, 0x44, 0xA4, 0x09, 0x38, 0x22, 0x29, 0x9F, 0x31, 0xD0, 0x08, 0x2E, 0xFA, 0x98, 0xEC, 0x4E, 0x6C, 0x89, 0x45, 0x28, 0x21, 0xE6, 0x38, 0xD0, 0x13, 0x77, 0xBE, 0x54, 0x66, 0xCF, 0x34, 0xE9, 0x0C, 0x6C, 0xC0, 0xAC, 0x29, 0xB7, 0xC9, 0x7C, 0x50, 0xDD, 0x3F, 0x84, 0xD5, 0xB5, 0xB5, 0x47, 0x09, 0x17, 0x92, 0x16, 0xD5, 0xD9, 0x89, 0x79, 0xFB, 0x1B, 0xD1, 0x31, 0x0B, 0xA6, 0x98, 0xDF, 0xB5, 0xAC, 0x2F, 0xFD, 0x72, 0xDB, 0xD0, 0x1A, 0xDF, 0xB7, 0xB8, 0xE1, 0xAF, 0xED, 0x6A, 0x26, 0x7E, 0x96, 0xBA, 0x7C, 0x90, 0x45, 0xF1, 0x2C, 0x7F, 0x99, 0x24, 0xA1, 0x99, 0x47, 0xB3, 0x91, 0x6C, 0xF7, 0x08, 0x01, 0xF2, 0xE2, 0x85, 0x8E, 0xFC, 0x16, 0x63, 0x69, 0x20, 0xD8, 0x71, 0x57, 0x4E, 0x69 };
        private static readonly byte[] PHI_PADDING = new byte[]
        { 0x9E, 0x37, 0x79, 0xB9, 0x7F, 0x4A, 0x7C, 0x15, 0xF3, 0x9C, 0xC0, 0x60, 0x5C, 0xED, 0xC8, 0x34, 0x10, 0x82, 0x27, 0x6B, 0xF3, 0xA2, 0x72, 0x51, 0xF8, 0x6C, 0x6A, 0x11, 0xD0, 0xC1, 0x8E, 0x95, 0x27, 0x67, 0xF0, 0xB1, 0x53, 0xD2, 0x7B, 0x7F, 0x03, 0x47, 0x04, 0x5B, 0x5B, 0xF1, 0x82, 0x7F, 0x01, 0x88, 0x6F, 0x09, 0x28, 0x40, 0x30, 0x02, 0xC1, 0xD6, 0x4B, 0xA4, 0x0F, 0x33, 0x5E, 0x36, 0xF0, 0x6A, 0xD7, 0xAE, 0x97, 0x17, 0x87, 0x7E, 0x85, 0x83, 0x9D, 0x6E, 0xFF, 0xBD, 0x7D, 0xC6, 0x64, 0xD3, 0x25, 0xD1, 0xC5, 0x37, 0x16, 0x82, 0xCA, 0xDD, 0x0C, 0xCC, 0xFD, 0xFF, 0xBB, 0xE1, 0x62, 0x6E, 0x33, 0xB8, 0xD0, 0x4B, 0x43, 0x31, 0xBB, 0xF7, 0x3C, 0x79, 0x0D, 0x94, 0xF7, 0x9D, 0x47, 0x1C, 0x4A, 0xB3, 0xED, 0x3D, 0x82, 0xA5, 0xFE, 0xC5, 0x07, 0x70, 0x5E, 0x4A, 0xE6, 0xE5 };

        public byte[] Compute(MessageToHashReader source)
        {
            // INIT
            // Init hash variables (in derivate class)
            var bufferLength = this._bufferLength;
            InitState(out IQmhHukState hashState);

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
            if ((bytesRead + 11) > bufferLength)  // 11 = 1 (bit tail) + 2 (bit HASH len) + 8 (bit DATA len)
                blocksLeft++;

            // 0x80 tail and PI padding
            buffer[bytesRead] = 0x80;
            for (int p = bytesRead + 1, pi = 0; p < bufferLength; p++, pi++)
                buffer[p] = PI_PADDING[pi];

            // Process extra blocks
            if (blocksLeft > 1) // if two extra blocks
            {
                Compress(hashState, buffer);
                buffer = new byte[bufferLength];
                Buffer.BlockCopy(PHI_PADDING, 0, buffer, 0, bufferLength);
            }
            // last extra block
            {
                // set HASH bitLen
                buffer[bufferLength - 10] = _bitLenMark[0];
                buffer[bufferLength -  9] = _bitLenMark[1];
                // set DATA bitLen
                byte[] length = BitConverter.GetBytes(bitLength);
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(length);
                Buffer.BlockCopy(length, 0, buffer, bufferLength - 8, 8);
                Compress(hashState, buffer);
            }

            // Finalize hash and truncate (Output Transformation)
            return FinalHash(hashState);
        }

        protected interface IQmhHukState { };
    }

    public class QmhHuk256 : QmhHuk
    {
        /// <summary>
        /// Round constants for QmhHuk/224 and QmhHuk/256
        /// </summary>
        private static readonly UInt32[] K = new UInt32[56] { // 419..769
            0x7BA0EA2D, 0x7EABF2D0, 0x8DBE8D03, 0x90BB1721, 0x99A2AD45, 0x9F86E289, 0xA84C4472, 0xB3DF34FC,
            0xB99BB8D7, 0xBC76CBAB, 0xC226A69A, 0xD304F19A, 0xDE1BE20A, 0xE39BB437, 0xEE84927C, 0xF3EDD277,
            0xFBFDFE53, 0x774DBCCB, 0x91A0F121, 0x25F57204, 0x2DA45582, 0x3A52C34C, 0x41DC0172, 0x495796FC,
            0x4BD31FC6, 0x533CDE21, 0x5F7ABFE3, 0x66C206B3, 0x6DFCC6BC, 0x7062F20F, 0x778D5127, 0x7EABA3CC,
            0x8363ECCC, 0x85BE1C25, 0x93C04028, 0x9F4A205F, 0xA1953565, 0xA627BB0F, 0xACFA8089, 0xB3C29B23,
            0xB602F6FA, 0xC36CEE0A, 0xC7DC81EE, 0xCE7B8471, 0xD740288C, 0xE21DBA7A, 0xEABBFF66, 0xF56A9E60,
            0xFDE41D72, 0x2A1025E6, 0x68DF293A, 0x928E35C6, 0xE579F4FB, 0x1D20CDCD, 0x213AF85A, 0x2964505C
        };

        private class QmhHuk256State : IQmhHukState
        {
            public UInt32[] H;
        }

        /// <summary>
        /// Init hsha state
        /// </summary>
        /// <param name="hashState"></param>
        protected override void InitState(out IQmhHukState hashState)
        {
            if (this._bitLen == 256)
                hashState = new QmhHuk256State()
                {
                    H = new UInt32[] { // 419..457
                        0x78307697, 0x84AE4B7C, 0xC2B2B755, 0xCF03D20E,
                        0xF3CBB117, 0x79C450F6, 0x308AF161, 0x60A7A998
                    }
                };
            else
                hashState = new QmhHuk256State()
                {
                    H = new UInt32[] { // 461..503
                        0x788D9812, 0x84769B42, 0x9C34F062, 0xE2D564C4,
                        0xAE469BE4, 0x2894C107, 0x569B58C6, 0x6D7B3939
                    }
                };
        }

        protected override void Compress(IQmhHukState hashState, byte[] buffer)
        {
            // Init Message Schedule array (W)
            UInt32[] W = new UInt32[56];
            for (int t = 0, j = 0; t < 16; ++t, j += 4)
                W[t] = (UInt32)((buffer[j] << 24) | (buffer[j + 1] << 16) | (buffer[j + 2] << 8) | (buffer[j + 3]));
            for (int t = 16; t < 56; ++t)
                W[t] = Wsigma1(W[t - 2]) + W[t - 7] + Wsigma0(W[t - 15]) + W[t - 16];

            QmhHuk256State state = (QmhHuk256State)hashState;
            // Init working variables
            UInt32 a = state.H[0];
            UInt32 b = state.H[1];
            UInt32 c = state.H[2];
            UInt32 d = state.H[3];
            UInt32 e = state.H[4];
            UInt32 f = state.H[5];
            UInt32 g = state.H[6];
            UInt32 h = state.H[7];

            // 56 rounds
            for (int r = 0; r < 56; ++r)
            {
                UInt32 T1 = h + Sigma1(e) + Choice(e, f, g) + K[r] + W[r];
                UInt32 T2 = Sigma0(a) + Majority(a, b, c);
                UInt32 T3 = a + Sigma1(d) + Choice(c, b, a) + K[r] + W[r];
                UInt32 T4 = Sigma0(h) + Majority(h, g, f);
                h = g;
                g = f ^ T1;
                f = e;
                e = T3 + T4;
                d = c;
                c = b ^ T3;
                b = a;
                a = T1 + T2;
            }

            // Update hash state
            state.H[0] ^= a;
            state.H[1] ^= b;
            state.H[2] ^= c;
            state.H[3] ^= d;
            state.H[4] ^= e;
            state.H[5] ^= f;
            state.H[6] ^= g;
            state.H[7] ^= h;
        }

        protected override byte[] FinalHash(IQmhHukState hashState)
        {
            var size = 8;
            if (this._bitLen == 224) size = 7;
            byte[] result = new byte[size * 4];

            QmhHuk256State state = (QmhHuk256State)hashState;
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
            return ((x >> 3) | (x << 29)) ^ ((x >> 11) | (x << 21)) ^ ((x >> 23) | (x << 9));
        }

        private static UInt32 Sigma1(UInt32 x)
        {
            return ((x >> 7) | (x << 25)) ^ ((x >> 15) | (x << 17)) ^ ((x >> 24) | (x << 8));
        }

        private static UInt32 Wsigma0(UInt32 x)
        {
            return ((x >> 9) | (x << 23)) ^ ((x >> 14) | (x << 18)) ^ ((x >> 3) | (x << 29));
        }

        private static UInt32 Wsigma1(UInt32 x)
        {
            return ((x >> 15) | (x << 17)) ^ ((x >> 13) | (x << 19)) ^ ((x >> 10) | (x << 22));
        }
    }

    public class QmhHuk512 : QmhHuk
    {
        /// <summary>
        /// Round constants for QmhHuk/384 and QmhHuk/512
        /// </summary>
        private static readonly UInt64[] K = new UInt64[64] { // 419..827
            0x7BA0EA2D98160007, 0x7EABF2D0C21F964A, 0x8DBE8D038B409545, 0x90BB1721582E8285,
            0x99A2AD45936D4E61, 0x9F86E289FE03E739, 0xA84C4472FAA9A82F, 0xB3DF34FCE89E0532,
            0xB99BB8D7B173534F, 0xBC76CBAB1AEA1F9C, 0xC226A69A780F3CC3, 0xD304F19AA233957D,
            0xDE1BE20A212129DD, 0xE39BB43755141950, 0xEE84927CEA48DDD2, 0xF3EDD2773C523B67,
            0xFBFDFE53A8D32F2A, 0x774DBCCB2AF22D78, 0x91A0F12170E62F5E, 0x25F57204C725BED8,
            0x2DA45582CD598B32, 0x3A52C34C203BFCF3, 0x41DC0172CD1991C1, 0x495796FCB33CC1C0,
            0x4BD31FC693F9F16E, 0x533CDE2115F5A9A0, 0x5F7ABFE36E99C1D3, 0x66C206B310A57E6F,
            0x6DFCC6BC39603F61, 0x7062F20F86FD1052, 0x778D51277ADEC865, 0x7EABA3CC25DA7048,
            0x8363ECCC37A5BE05, 0x85BE1C253BEBA54E, 0x93C04028F348BBC5, 0x9F4A205FD05B2148,
            0xA19535651CA6D2DE, 0xA627BB0FBF027BC7, 0xACFA80891DA2F06B, 0xB3C29B23031A7F9D,
            0xB602F6FAC7D3D74D, 0xC36CEE0A10C7BA49, 0xC7DC81EEA9EBAD4F, 0xCE7B8471B0F809DF,
            0xD740288C84DF269C, 0xE21DBA7AC2290607, 0xEABBFF66BE175964, 0xF56A9E60F62CEA92,
            0xFDE41D729D126EAB, 0x2A1025E68E9D0B0E, 0x68DF293A67720745, 0x928E35C63606831A,
            0xE579F4FBCDD87B50, 0x1D20CDCD45B8DE1E, 0x213AF85A39B0C320, 0x2964505C52A2F35B,
            0x2D738E114181E082, 0x3B8CEA0E71C58AAF, 0x4584E6AE9F54016E, 0x515F4356903DCCC2,
            0x5356112DDFD5A8E9, 0x5D1BC3EDBE2C897A, 0x5F0DA9F8ED53548B, 0x62EF0BE4D5492E78
        };

        private class QmhHuk512State : IQmhHukState
        {
            public UInt64[] H;
        }

        /// <summary>
        /// Init hsha state
        /// </summary>
        /// <param name="hashState"></param>
        protected override void InitState(out IQmhHukState hashState)
        {
            if (this._bitLen == 512)
                hashState = new QmhHuk512State()
                {
                    H = new UInt64[] {
                        0x7830769755FE0B0A, 0x84AE4B7CB79286A4, 0xC2B2B7559233F645, 0xCF03D20E5ACFA987,
                        0xF3CBB117DBF3C297, 0x79C450F6CE64CB45, 0x308AF161F4A4E085, 0x60A7A9985B936A57
                    }
                };
            else
                hashState = new QmhHuk512State()
                {
                    H = new UInt64[] {
                        0x788D9812FBEB2197, 0x84769B42A93033FE, 0x9C34F0620BFEF64A, 0xE2D564C44CA0D2CD,
                        0xAE469BE46D4C8CA9, 0x2894C1073A16F2FE, 0x569B58C652391DBE, 0x6D7B3939EC6A09C2
                    }
                };
        }

        protected override void Compress(IQmhHukState hashState, byte[] buffer)
        {
            // Init Message Schedule array (W)
            UInt64[] W = new UInt64[64];
            for (int t = 0, j = 0; t < 16; ++t, j += 8)
                W[t] = ((UInt64)buffer[j    ] << 56) | ((UInt64)buffer[j + 1] << 48) | ((UInt64)buffer[j + 2] << 40) | ((UInt64)buffer[j + 3] << 32) | 
                       ((UInt64)buffer[j + 4] << 24) | ((UInt64)buffer[j + 5] << 16) | ((UInt64)buffer[j + 6] <<  8) | ((UInt64)buffer[j + 7]);
            for (int t = 16; t < 64; ++t)
                W[t] = Wsigma1(W[t - 2]) + W[t - 7] + Wsigma0(W[t - 15]) + W[t - 16];

            QmhHuk512State state = (QmhHuk512State)hashState;
            // Init working variables
            UInt64 a = state.H[0];
            UInt64 b = state.H[1];
            UInt64 c = state.H[2];
            UInt64 d = state.H[3];
            UInt64 e = state.H[4];
            UInt64 f = state.H[5];
            UInt64 g = state.H[6];
            UInt64 h = state.H[7];

            // 64 rounds
            for (int r = 0; r < 64; ++r)
            {
                UInt64 T1 = h + Sigma1(e) + Choice(e, f, g) + K[r] + W[r];
                UInt64 T2 = Sigma0(a) + Majority(a, b, c);
                UInt64 T3 = a + Sigma1(d) + Choice(c, b, a) + K[r] + W[r];
                UInt64 T4 = Sigma0(h) + Majority(h, g, f);
                h = g;
                g = f ^ T1;
                f = e;
                e = T3 + T4;
                d = c;
                c = b ^ T3;
                b = a;
                a = T1 + T2;
            }

            // Update hash state
            state.H[0] ^= a;
            state.H[1] ^= b;
            state.H[2] ^= c;
            state.H[3] ^= d;
            state.H[4] ^= e;
            state.H[5] ^= f;
            state.H[6] ^= g;
            state.H[7] ^= h;
        }

        protected override byte[] FinalHash(IQmhHukState hashState)
        {
            var size = 8;
            if (this._bitLen == 384) size = 6;
            byte[] result = new byte[size * 8];

            QmhHuk512State state = (QmhHuk512State)hashState;
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
            return ((x >> 30) | (x << 34)) ^ ((x >> 26) | (x << 38)) ^ ((x >> 19) | (x << 45));
        }

        private static UInt64 Sigma1(UInt64 x)
        {
            return ((x >> 44) | (x << 20)) ^ ((x >> 14) | (x << 50)) ^ ((x >> 31) | (x << 33));
        }

        private static UInt64 Wsigma0(UInt64 x)
        {
            return ((x >> 3) | (x << 61)) ^ ((x >> 18) | (x << 46)) ^ ((x >> 7) | (x << 57));
        }

        private static UInt64 Wsigma1(UInt64 x)
        {
            return ((x >> 39) | (x << 25)) ^ ((x >> 59) | (x << 5)) ^ ((x >> 6) | (x << 58));
        }
    }

    /// <summary>
    /// HashAlgorithm implementation for QmhHuk
    /// </summary>
    public class QmhHukHashAlgorithm : HashAlgorithm
    {
        private int _bitLen;
        private QmhHuk _qdhHuk;
        private byte[] _finalHash;
        private MemoryStream _stream;

        private QmhHukHashAlgorithm(int bitLen)
        {
            this._bitLen = bitLen;
            this._qdhHuk = QmhHuk.Create(bitLen);
            this._finalHash = null;
            this._stream = new MemoryStream();
        }

        public static QmhHukHashAlgorithm Create(int bitLen)
        {
            return new QmhHukHashAlgorithm(bitLen);
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            this._stream.Write(array, ibStart, cbSize);
        }

        protected override byte[] HashFinal()
        {
            this._stream.Seek(0, SeekOrigin.Begin);
            this._finalHash = this._qdhHuk.Compute(new StreamToHashReader(this._stream));
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
                return String.Format("QmhHuk {0}: {1}", this.HashSize, String.Join("", this._finalHash.Select(b => b.ToString("X2"))));
            else
                return String.Format("QmhHuk {0}", this.HashSize);
        }
    }
}