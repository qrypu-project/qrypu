/*
 * (C) 2018 José Hurtado
 * 
 * ES: Manipulación de bytes para labrado
 * 
 * Licencia: para este archivo se aplica: https://opensource.org/licenses/MIT
 */
namespace qrypu.Core.Farming
{
    using System;
    using System.Security.Cryptography;

    /// <summary>
    /// ES: Contiene funciones de ayuda al proceso de labrado
    /// </summary>
    public static class FarmingBytes
    {
        /// <summary>
        /// ES: Desempaqueta una serie de bytes a partir de un formato comprimido como se define para
        /// "Bits" de Bitcoin (https://bitcoin.org/en/developer-documentation)
        /// </summary>
        /// <param name="packed">ES: formato empaquetado a 32bit</param>
        /// <param name="length">ES: Tamaño del array de bytes extendido</param>
        /// <returns>ES: Array de bytes</returns>
        public static byte[] Unpack(this UInt32 packed, int length = 32)
        {
            var result = new byte[length];

            var index = length - (packed >> 24);
            result[index++] = (byte)(packed >> 16);
            result[index++] = (byte)(packed >> 8);
            result[index] = (byte)(packed >> 0);

            return result;
        }

        /// <summary>
        /// ES: Calcula la versión empaquetada para un número de ceros inicial
        /// </summary>
        /// <param name="zeros">ES: Número de ceros iniciales</param>
        /// <param name="length">ES: Largo total del array</param>
        /// <returns>ES: Versión empaquetada a 32bit</returns>
        public static UInt32 PackFromZeros(int zeros, int length = 32)
        {
            var completeBytes = zeros / 8;
            var size = (byte)(length - completeBytes);
            var flagByte = 0xFF >> (zeros % 8);

            return (UInt32)((size << 24) + (flagByte << 16) + 0xFFFF);
        }

        /// <summary>
        /// ES: Comparación de arrays de bytes.
        /// Cumple contrato de delegado FarmingChallenge
        /// </summary>
        /// <param name="data">ES: Bytes a comparar</param>
        /// <param name="target">ES: Valor de referencia</param>
        /// <returns>ES: true cuando data equivale a un número menor o igual que
        /// target en formato Bigendian</returns>
        public static bool LessOrEqualThan(byte[] data, byte[] target)
        {
            var dataLength = data.Length;
            if (dataLength != target.Length) return false;
            int d = 0;
            for (; d < dataLength && data[d] == target[d]; d++) ; // skip all equals
            if (d < dataLength)
                return data[d] <= target[d]; // depends on first different
            else
                return true; // all was equal
        }

        /// <summary>
        /// ES: Comparación de arrays de bytes.
        /// Cumple contrato de delegado FarmingChallenge
        /// </summary>
        /// <param name="data">ES: Bytes a comparar</param>
        /// <param name="target">ES: Valor de referencia</param>
        /// <returns>ES: true cuando data empieza con los mismos bytes que target</returns>
        public static bool StartsWith(byte[] data, byte[] target)
        {
            var targetLength = target.Length;
            if (data.Length < targetLength) return false;
            int t = 0;
            for (; t < targetLength && data[t] == target[t]; t++) ; // while equal
            return (t == targetLength);
        }

        /// <summary>
        /// ES: Cambia los bytes al principio de los datos
        /// </summary>
        /// <param name="data">ES: Datos a cambiar</param>
        /// <param name="head">ES: Nueva cabecera</param>
        /// <returns>ES: Posición del cambio</returns>
        public static int ChangeHead(this byte[] data, byte[] head)
        {
            if (head.Length > data.Length)
                throw new OverflowException();
            head.CopyTo(data, 0);
            return 0;
        }

        /// <summary>
        /// ES: Cambiar los byteas al final de los datos
        /// </summary>
        /// <param name="data">ES: Datos a cambiar</param>
        /// <param name="tail">ES: Nuevos datos al final</param>
        /// <returns>ES: Posición del cambio</returns>
        public static int ChangeTail(this byte[] data, byte[] tail)
        {
            if (tail.Length > data.Length)
                throw new OverflowException();
            var index = data.Length - tail.Length;
            tail.CopyTo(data, index);
            return index;
        }

        /// <summary>
        /// ES: Incrementa el valor del Nonce en una posición dada
        /// </summary>
        /// <param name="data">ES: Datos incluyendo Nonce</param>
        /// <param name="index">ES: Posición del Nonce</param>
        /// <param name="length">ES: Tamaño del Nonce a incrementar</param>
        /// <returns>ES: true si el incremento está dentro de los límites del tamaño de Nonce</returns>
        public static bool IncNonce(this byte[] data, int index, int length)
        {
            int incLength = index + length;

            var inc = 1;
            for (int ptr = index; ptr < incLength && inc > 0; ptr++)
            {
                int sum = data[ptr] + inc;
                data[ptr] = (byte)(sum & 0xFF);
                inc = sum >> 8;
            }
            if (inc > 0)
            {
                for (int i = index; i < incLength; i++)
                    data[i] = 0;
                data[index] = (byte)inc;
                return false;
            }
            return true;
        }

        /// <summary>
        /// ES: Obtiene el Nonce de los datos
        /// </summary>
        /// <param name="data">ES: Datos incluyendo Nonce</param>
        /// <param name="index">ES: Posición del Nonce</param>
        /// <param name="count">ES: Tamaño del Nonce</param>
        /// <returns>ES: Nonce extraído</returns>
        public static byte[] ExtractNonce(this byte[] data, int index, int count)
        {
            if (index + count > data.Length) return null;

            var result = new byte[count];
            for (int i = 0; i < count; i++)
            {
                result[i] = data[index++];
            }
            return result;
        }

        /// <summary>
        /// ES: Comparación de Nonces
        /// </summary>
        /// <param name="left">ES: Nonce a comparar</param>
        /// <param name="rigth">ES: Nonce a comparar</param>
        /// <returns>ES: true si los Nonce son iguales</returns>
        public static bool NoncesAreEqual(byte[] left, byte[] rigth)
        {
            if (left == rigth) return true; // same object
            if (left == null || rigth == null) return false; // one side are null
            if (left.Length != rigth.Length) return false; // one side is larger

            for (int i = 0; i < left.Length; i++)
            {
                if (left[i] != rigth[i]) return false; // one byte different
            }
            return true; // arrays are equal
        }

        /// <summary>
        /// ES: Generador de Nonce aleatorios
        /// </summary>
        private static RandomNumberGenerator _seedNonceGen = RandomNumberGenerator.Create();
        
        /// <summary>
        /// ES: Genera un Nonce aleatorio
        /// </summary>
        /// <param name="nonceLength">ES: Tamaño del Nonce</param>
        /// <returns>ES: Nonce generado</returns>
        public static byte[] SeedNonce(int nonceLength)
        {
            var result = new byte[nonceLength];
            _seedNonceGen.GetBytes(result);
            return result;
        }
    }
}