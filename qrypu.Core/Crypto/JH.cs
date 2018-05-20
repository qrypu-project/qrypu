/*
 * (C) 2018 José Hurtado
 * 
 * ES: Implementación del algoritmo JH, finalista del concurso NIST para SHA3
 * Se limita a mensajes de bytes enteros y está preparado para procesar streams
 * Este código está probado con los mensajes propuestos por NIST y los resultados 
 * entregados por Hongjun Wu, creador del algoritmo.
 * 
 * Licencia: para este archivo se aplica: https://opensource.org/licenses/MIT
 */
namespace qrypu.Core.Crypto
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;

    public class JH : ICryptoHash
    {
        private static readonly UInt64[,] JH224_H0 = {
            { 0x2DFEDD62F99A98AC, 0xAE7CACD619D634E7 },
            { 0xA4831005BC301216, 0xB86038C6C9661494 },
            { 0x66D9899F2580706F, 0xCE9EA31B1D9B1ADC },
            { 0x11E8325F7B366E10, 0xF994857F02FA06C1 },
            { 0x1B4F1B5CD8C840B3, 0x97F6A17F6E738099 },
            { 0xDCDF93A5ADEAA3D3, 0xA431E8DEC9539A68 },
            { 0x22B4A98AEC86A1E4, 0xD574AC959CE56CF0 },
            { 0x15960DEAB5AB2BBF, 0x9611DCF0DD64EA6E }
        };

        private static readonly UInt64[,] JH256_H0 = {
            { 0xEB98A3412C20D3EB, 0x92CDBE7B9CB245C1 },
            { 0x1C93519160D4C7FA, 0x260082D67E508A03 },
            { 0xA4239E267726B945, 0xE0FB1A48D41A9477 },
            { 0xCDB5AB26026B177A, 0x56F024420FFF2FA8 },
            { 0x71A396897F2E4D75, 0x1D144908F77DE262 },
            { 0x277695F776248F94, 0x87D5B6574780296C },
            { 0x5C5E272DAC8E0D6C, 0x518450C657057A0F },
            { 0x7BE4D367702412EA, 0x89E3AB13D31CD769 }
        };

        private static readonly UInt64[,] JH384_H0 = {
            { 0x481E3BC6D813398A, 0x6D3B5E894ADE879B },
            { 0x63FAEA68D480AD2E, 0x332CCB21480F8267 },
            { 0x98AEC84D9082B928, 0xD455EA3041114249 },
            { 0x36F555B2924847EC, 0xC7250A93BAF43CE1 },
            { 0x569B7F8A27DB454C, 0x9EFCBD496397AF0E },
            { 0x589FC27D26AA80CD, 0x80C08B8C9DEB2EDA },
            { 0x8A7981E8F8D5373A, 0xF43967ADDDD17A71 },
            { 0xA9B4D3BDA475D394, 0x976C3FBA9842737F }
        };

        private static readonly UInt64[,] JH512_H0 = {
            { 0x6FD14B963E00AA17, 0x636A2E057A15D543 },
            { 0x8A225E8D0C97EF0B, 0xE9341259F2B3C361 },
            { 0x891DA0C1536F801E, 0x2AA9056BEA2B6D80 },
            { 0x588ECCDB2075BAA6, 0xA90F3A76BAF83BF7 },
            { 0x0169E60541E34A69, 0x46B58A8E2E6FE65A },
            { 0x1047A7D0C1843C24, 0x3B6E71B12D5AC199 },
            { 0xCF57F6EC9DB1F856, 0xA706887C5716B156 },
            { 0xE3C2FCDFE68517FB, 0x545A4678CC8CDD4B }
        };

        private static readonly UInt64[,] SUBSTITUTION_BOX = {
            { 0x72D5DEA2DF15F867, 0x7B84150AB7231557, 0x81ABD6904D5A87F6, 0x4E9F4FC5C3D12B40 },
            { 0xEA983AE05C45FA9C, 0x03C5D29966B2999A, 0x660296B4F2BB538A, 0xB556141A88DBA231 },
            { 0x03A35A5C9A190EDB, 0x403FB20A87C14410, 0x1C051980849E951D, 0x6F33EBAD5EE7CDDC },
            { 0x10BA139202BF6B41, 0xDC786515F7BB27D0, 0x0A2C813937AA7850, 0x3F1ABFD2410091D3 },
            { 0x422D5A0DF6CC7E90, 0xDD629F9C92C097CE, 0x185CA70BC72B44AC, 0xD1DF65D663C6FC23 },
            { 0x976E6C039EE0B81A, 0x2105457E446CECA8, 0xEEF103BB5D8E61FA, 0xFD9697B294838197 },
            { 0x4A8E8537DB03302F, 0x2A678D2DFB9F6A95, 0x8AFE7381F8B8696C, 0x8AC77246C07F4214 },
            { 0xC5F4158FBDC75EC4, 0x75446FA78F11BB80, 0x52DE75B7AEE488BC, 0x82B8001E98A6A3F4 },
            { 0x8EF48F33A9A36315, 0xAA5F5624D5B7F989, 0xB6F1ED207C5AE0FD, 0x36CAE95A06422C36 },
            { 0xCE2935434EFE983D, 0x533AF974739A4BA7, 0xD0F51F596F4E8186, 0x0E9DAD81AFD85A9F },
            { 0xA7050667EE34626A, 0x8B0B28BE6EB91727, 0x47740726C680103F, 0xE0A07E6FC67E487B },
            { 0x0D550AA54AF8A4C0, 0x91E3E79F978EF19E, 0x8676728150608DD4, 0x7E9E5A41F3E5B062 },
            { 0xFC9F1FEC4054207A, 0xE3E41A00CEF4C984, 0x4FD794F59DFA95D8, 0x552E7E1124C354A5 },
            { 0x5BDF7228BDFE6E28, 0x78F57FE20FA5C4B2, 0x05897CEFEE49D32E, 0x447E9385EB28597F },
            { 0x705F6937B324314A, 0x5E8628F11DD6E465, 0xC71B770451B920E7, 0x74FE43E823D4878A },
            { 0x7D29E8A3927694F2, 0xDDCB7A099B30D9C1, 0x1D1B30FB5BDC1BE0, 0xDA24494FF29C82BF },
            { 0xA4E7BA31B470BFFF, 0x0D324405DEF8BC48, 0x3BAEFC3253BBD339, 0x459FC3C1E0298BA0 },
            { 0xE5C905FDF7AE090F, 0x947034124290F134, 0xA271B701E344ED95, 0xE93B8E364F2F984A },
            { 0x88401D63A06CF615, 0x47C1444B8752AFFF, 0x7EBB4AF1E20AC630, 0x4670B6C5CC6E8CE6 },
            { 0xA4D5A456BD4FCA00, 0xDA9D844BC83E18AE, 0x7357CE453064D1AD, 0xE8A6CE68145C2567 },
            { 0xA3DA8CF2CB0EE116, 0x33E906589A94999A, 0x1F60B220C26F847B, 0xD1CEAC7FA0D18518 },
            { 0x32595BA18DDD19D3, 0x509A1CC0AAA5B446, 0x9F3D6367E4046BBA, 0xF6CA19AB0B56EE7E },
            { 0x1FB179EAA9282174, 0xE9BDF7353B3651EE, 0x1D57AC5A7550D376, 0x3A46C2FEA37D7001 },
            { 0xF735C1AF98A4D842, 0x78EDEC209E6B6779, 0x41836315EA3ADBA8, 0xFAC33B4D32832C83 },
            { 0xA7403B1F1C2747F3, 0x5940F034B72D769A, 0xE73E4E6CD2214FFD, 0xB8FD8D39DC5759EF },
            { 0x8D9B0C492B49EBDA, 0x5BA2D74968F3700D, 0x7D3BAED07A8D5584, 0xF5A5E9F0E4F88E65 },
            { 0xA0B8A2F436103B53, 0x0CA8079E753EEC5A, 0x9168949256E8884F, 0x5BB05C55F8BABC4C },
            { 0xE3BB3B99F387947B, 0x75DAF4D6726B1C5D, 0x64AEAC28DC34B36D, 0x6C34A550B828DB71 },
            { 0xF861E2F2108D512A, 0xE3DB643359DD75FC, 0x1CACBCF143CE3FA2, 0x67BBD13C02E843B0 },
            { 0x330A5BCA8829A175, 0x7F34194DB416535C, 0x923B94C30E794D1E, 0x797475D7B6EEAF3F },
            { 0xEAA8D4F7BE1A3921, 0x5CF47E094C232751, 0x26A32453BA323CD2, 0x44A3174A6DA6D5AD },
            { 0xB51D3EA6AFF2C908, 0x83593D98916B3C56, 0x4CF87CA17286604D, 0x46E23ECC086EC7F6 },
            { 0x2F9833B3B1BC765E, 0x2BD666A5EFC4E62A, 0x06F4B6E8BEC1D436, 0x74EE8215BCEF2163 },
            { 0xFDC14E0DF453C969, 0xA77D5AC406585826, 0x7EC1141606E0FA16, 0x7E90AF3D28639D3F },
            { 0xD2C9F2E3009BD20C, 0x5FAACE30B7D40C30, 0x742A5116F2E03298, 0x0DEB30D8E3CEF89A },
            { 0x4BC59E7BB5F17992, 0xFF51E66E048668D3, 0x9B234D57E6966731, 0xCCE6A6F3170A7505 },
            { 0xB17681D913326CCE, 0x3C175284F805A262, 0xF42BCBB378471547, 0xFF46548223936A48 },
            { 0x38DF58074E5E6565, 0xF2FC7C89FC86508E, 0x31702E44D00BCA86, 0xF04009A23078474E },
            { 0x65A0EE39D1F73883, 0xF75EE937E42C3ABD, 0x2197B2260113F86F, 0xA344EDD1EF9FDEE7 },
            { 0x8BA0DF15762592D9, 0x3C85F7F612DC42BE, 0xD8A7EC7CAB27B07E, 0x538D7DDAAA3EA8DE },
            { 0xAA25CE93BD0269D8, 0x5AF643FD1A7308F9, 0xC05FEFDA174A19A5, 0x974D66334CFD216A },
            { 0x35B49831DB411570, 0xEA1E0FBBEDCD549B, 0x9AD063A151974072, 0xF6759DBF91476FE2 }
        };

        private const int BUFFER_LEN = 64;

        private delegate UInt64 Swapper(UInt64 value);
        private static Swapper[] _swappers;

        static JH()
        {
            _swappers = new Swapper[6];
            _swappers[0] = (value) => (((value & 0x5555555555555555) << 1) | ((value & 0xAAAAAAAAAAAAAAAA) >> 1));
            _swappers[1] = (value) => (((value & 0x3333333333333333) << 2) | ((value & 0xCCCCCCCCCCCCCCCC) >> 2));
            _swappers[2] = (value) => (((value & 0x0F0F0F0F0F0F0F0F) << 4) | ((value & 0xF0F0F0F0F0F0F0F0) >> 4));
            _swappers[3] = (value) => (((value & 0x00FF00FF00FF00FF) << 8) | ((value & 0xFF00FF00FF00FF00) >> 8));
            _swappers[4] = (value) => (((value & 0x0000FFFF0000FFFF) << 16) | ((value & 0xFFFF0000FFFF0000) >> 16));
            _swappers[5] = (value) => ((value << 32) | (value >> 32));

#if BIGENDIAN
            BigEndianInvert(JH224_H0, 8, 2);
            BigEndianInvert(JH256_H0, 8, 2);
            BigEndianInvert(JH384_H0, 8, 2);
            BigEndianInvert(JH512_H0, 8, 2);
            BigEndianInvert(SUBSTITUTION_BOX, 42, 4);
#endif
        }

#if BIGENDIAN
        private static void BigEndianInvert(UInt64[,] array, int rowCount, int colCount)
        {
            for (int r = 0; r < rowCount; r++)
            {
                for (int c = 0; c < colCount; c++)
                {
                    var bytes = BitConverter.GetBytes(array[r, c]);
                    Array.Reverse(bytes);
                    array[r, c] = BitConverter.ToUInt64(bytes, 0);
                }
            }
        }
#endif

        /// <summary>
        /// Creates a new instance of JH hasher configured for the result bit length specified
        /// </summary>
        /// <param name="bitLen">Bits for result: 224, 256, 384 or 512</param>
        /// <returns>Hasher instance</returns>
        public static JH Create(int bitLen)
        {
            if ((bitLen != 224) && (bitLen != 256) && (bitLen != 384) && (bitLen != 512))
                throw new ArgumentException();

            var result = new JH();

            result.Config(bitLen);
            return result;
        }

        /// <summary>
        /// Internal variables are set by Config method.
        /// An instance can Compute multiple hashes while result bit len not change.
        /// </summary>
        private UInt64[,] _initState;

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
                    this._initState = JH224_H0;
                    break;
                case 256:
                    this._initState = JH256_H0;
                    break;
                case 384:
                    this._initState = JH384_H0;
                    break;
                case 512:
                    this._initState = JH512_H0;
                    break;
                default:
                    throw new ArgumentException();
            }
            this._bitLen = bitLen;
        }

        /// <summary>
        /// Compute hash from message source
        /// </summary>
        /// <param name="source">Stream or buffer</param>
        /// <returns>Hash computed</returns>
        public byte[] Compute(MessageToHashReader source)
        {
            // INIT
            // Init hash buffer
            UInt64[,] hashState = new UInt64[8, 2];
            for (int row = 0; row < 8; row++)
            {
                hashState[row, 0] = this._initState[row, 0];
                hashState[row, 1] = this._initState[row, 1];
            }

            // UPDATE
            // Transform complete blocks
            byte[] buffer = new byte[BUFFER_LEN];
            ulong blockCount = 0;
            long allBytesRead = 0;
            int bytesRead;
            while ((bytesRead = source.Read(buffer, 0, BUFFER_LEN)) == BUFFER_LEN)
            {
                allBytesRead += bytesRead;
                Compress(hashState, buffer);
                blockCount++;
            }
            allBytesRead += bytesRead;
            ulong bitCount = (ulong)(allBytesRead << 3);

            // FINAL
            ulong bitPadding = 384 + (ulong)((((-(long)bitCount) % 512) + 512) % 512);
            ulong totalBlocks = (bitCount + bitPadding + 128) / 512;
            int blocksLeft = (int)(totalBlocks - blockCount);

            // 0x80 tail and zero padding
            buffer[bytesRead] = 0x80;
            for (int p = bytesRead + 1; p < BUFFER_LEN; p++)
                buffer[p] = 0x00;

            // Process extra blocks
            if (blocksLeft > 1) // if two extra blocks
            {
                Compress(hashState, buffer);
                buffer = new byte[BUFFER_LEN];
            }
            // last extra block
            {
                byte[] bytes = BitConverter.GetBytes(bitCount);
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(bytes);
                Buffer.BlockCopy(bytes, 0, buffer, BUFFER_LEN - 8, 8);
                Compress(hashState, buffer);
            }

            var result = PlainHash(hashState);

            return result;
        }

        private UInt64[] ToBlock(byte[] buffer)
        {
            var block = new UInt64[8];
#if !BIGENDIAN
            // Little Endian
            var leBuffer = new byte[BUFFER_LEN];
            Buffer.BlockCopy(buffer, 0, leBuffer, 0, BUFFER_LEN);
            Array.Reverse(leBuffer);
            for (int i = 7, b = 0; i >= 0; i--, b++)
            {
                block[b] = BitConverter.ToUInt64(leBuffer, i << 3);
            }
#else
            for (int b = 0; b < 8; b++)
            {
                block[b] = BitConverter.ToUInt64(buffer, b << 3);
            }
#endif
            return block;
        }

        private byte[] PlainHash(UInt64[,] hashState)
        {
            byte[] buffer = new byte[BUFFER_LEN * 2]; // 1024 bits or 128 bytes
            for (int row = 0; row < 8; row++)
            {
                for (int col = 0; col < 2; col++)
                {
                    var bytes = BitConverter.GetBytes(hashState[row, col]);
#if !BIGENDIAN
                    Array.Reverse(bytes);
#endif
                    Buffer.BlockCopy(bytes, 0, buffer, (row << 4) + (col << 3), 8);
                }
            }

            int count = this._bitLen >> 3;
            int start = 128 - count;
            var result = new byte[count];
            Buffer.BlockCopy(buffer, start, result, 0, count);

            return result;
        }

        private void Compress(UInt64[,] hashState, byte[] buffer)
        {
            var block = ToBlock(buffer);

            for (int i = 0; i < 8; i++)
            {
                hashState[i >> 1, i & 1] ^= block[i];
            }

            Bijective(hashState);

            for (int i = 0; i < 8; i++)
            {
                hashState[(i + 8) >> 1, (i + 8) & 1] ^= block[i];
            }
        }

        private void Bijective(UInt64[,] hashState)
        {
            for (int i = 0; i < 42; i++)
                RoundFunction(hashState, i);
        }

        private void RoundFunction(UInt64[,] hashState, int round)
        {
            // SBox and MDS layer
            for (int i = 0; i < 2; i++)
            {
                SBox(hashState, i, 0, 2, 4, 6, SUBSTITUTION_BOX[round, i]);
                SBox(hashState, i, 1, 3, 5, 7, SUBSTITUTION_BOX[round, i + 2]);
                MDS(hashState, i);
            }

            // Swaping
            var layer = round % 7;
            if (layer < 6)
            {
                var swapper = _swappers[layer];
                for (var row = 1; row < 8; row += 2)
                {
                    hashState[row, 0] = swapper(hashState[row, 0]);
                    hashState[row, 1] = swapper(hashState[row, 1]);
                }
            }
            else
            {
                UInt64 swap;
                for (var row = 1; row < 8; row += 2)
                {
                    swap = hashState[row, 0];
                    hashState[row, 0] = hashState[row, 1];
                    hashState[row, 1] = swap;
                }
            }
        }

        /// <summary>
        /// Maximum Distance Separable
        /// </summary>
        private void MDS(UInt64[,] hashState, int col)
        {
            hashState[1, col] ^= hashState[2, col];
            hashState[3, col] ^= hashState[4, col];
            hashState[5, col] ^= hashState[0, col] ^ hashState[6, col];
            hashState[7, col] ^= hashState[0, col];
            hashState[0, col] ^= hashState[3, col];
            hashState[2, col] ^= hashState[5, col];
            hashState[4, col] ^= hashState[1, col] ^ hashState[7, col];
            hashState[6, col] ^= hashState[1, col];
            // m0=0, m1=2, m2=4, m3=6, m4=1, m5=3, m6=5, m7=7
        }

        /// <summary>
        /// Substitution box
        /// </summary>
        private void SBox(UInt64[,] hashState, int col, int row0, int row1, int row2, int row3, UInt64 subs)
        {
            var m3 = ~hashState[row3, col];
            var m2 = hashState[row2, col];
            var m0 = hashState[row0, col] ^ (~m2 & subs);
            var m1 = hashState[row1, col];
            var t0 = subs ^ (m0 & m1);
            m0 ^= m2 & m3;
            m3 ^= ~m1 & m2;
            m1 ^= m0 & m2;
            m2 ^= m0 & ~m3;
            m0 ^= m1 | m3;
            m3 ^= m1 & m2;
            m1 ^= t0 & m0;
            m2 ^= t0;

            hashState[row0, col] = m0;
            hashState[row1, col] = m1;
            hashState[row2, col] = m2;
            hashState[row3, col] = m3;
        }
    }

    /// <summary>
    /// HashAlgorithm implementation for JH
    /// </summary>
    public class JHHashAlgorithm : HashAlgorithm
    {
        private int _bitLen;
        private JH _jh;
        private byte[] _finalHash;
        private MemoryStream _stream;

        private JHHashAlgorithm(int bitLen)
        {
            this._bitLen = bitLen;
            this._jh = JH.Create(bitLen);
            this._finalHash = null;
            this._stream = new MemoryStream();
        }

        public static JHHashAlgorithm Create(int bitLen)
        {
            return new JHHashAlgorithm(bitLen);
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            this._stream.Write(array, ibStart, cbSize);
        }

        protected override byte[] HashFinal()
        {
            this._stream.Seek(0, SeekOrigin.Begin);
            this._finalHash = this._jh.Compute(new StreamToHashReader(this._stream));
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
                return String.Format("Grøstl {0}: {1}", this.HashSize, String.Join("", this._finalHash.Select(b => b.ToString("X2"))));
            else
                return String.Format("Grøstl {0}", this.HashSize);
        }
    }
}