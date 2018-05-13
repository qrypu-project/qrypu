/*
 * (C) 2018 José Hurtado
 * 
 * EN: Message source for hashing
 * ES: Origen de mensajes para hacer hashing
 * 
 * Licencia: para este archivo se aplica: https://opensource.org/licenses/MIT
 */
namespace qrypu.Core.Crypto
{
    using System;
    using System.IO;

    /// <summary>
    /// Message source for hashing.
    /// </summary>
    public abstract class MessageToHashReader
    {
        public abstract int Read(byte[] buffer, int offset, int count);
        public abstract long Length { get; }

        public static implicit operator MessageToHashReader(Stream stream)
        {
            return new StreamToHashReader(stream);
        }

        public static implicit operator MessageToHashReader(byte[] buffer)
        {
            return new BufferToHashReader(buffer);
        }
    }

    /// <summary>
    /// Wrapper for streams
    /// </summary>
    public class StreamToHashReader : MessageToHashReader
    {
        private readonly Stream _stream;

        public StreamToHashReader(Stream stream)
        {
            this._stream = stream;
        }

        public override long Length => this._stream.Length;

        public override int Read(byte[] buffer, int offset, int count)
        {
            return this._stream.Read(buffer, offset, count);
        }
    }

    /// <summary>
    /// Wrapper for byte arrays
    /// </summary>
    public class BufferToHashReader : MessageToHashReader
    {
        private readonly byte[] _buffer;
        private int _pointer;

        public BufferToHashReader(byte[] buffer)
        {
            this._buffer = buffer;
            this._pointer = 0;
        }

        public override long Length => this._buffer.LongLength;

        public override int Read(byte[] buffer, int offset, int count)
        {
            int remain = this._buffer.Length - this._pointer;
            if (count > remain)
                count = remain;

            Buffer.BlockCopy(this._buffer, this._pointer, buffer, offset, count);

            this._pointer += count;
            return count;
        }
    }
}