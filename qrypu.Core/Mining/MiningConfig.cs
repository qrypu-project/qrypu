/*
 * (C) 2018 José Hurtado
 * 
 * ES:
 * Licencia: para este archivo se aplica: https://opensource.org/licenses/MIT
 */
namespace qrypu.Core.Mining
{
    using qrypu.Core.Crypto;

    /// <summary>
    /// ES: Contrato para prueba de hash minado
    /// </summary>
    /// <param name="candidate">ES: Hash candidato</param>
    /// <param name="challenge">ES: Formato o condición a cumplir</param>
    /// <returns>ES: true si se cumplen con la condición</returns>
    public delegate bool MiningChallenge(byte[] candidate, byte[] challenge);

    /// <summary>
    /// ES: Posición de Nonce en los datos minados
    /// </summary>
    public enum MiningNoncePosition { Head, Tail }

    /// <summary>
    /// ES: Configuración de minado
    /// </summary>
    public class MiningConfig
    {
        /// <summary>
        /// ES: el Nonce se puede poner al principio o al final de los datos originales antes de calcular el hash
        /// Por defecto: Tail (al final)
        /// </summary>
        public MiningNoncePosition NoncePosition { get; set; }

        /// <summary>
        /// ES: el número de bytes del Nonce es variable, los valores más comunes serán 4 (UInt32) y 8 (UInt64)
        /// Por defecto: 8 (UInt64)
        /// </summary>
        public byte NonceLength { get; set; }

        /// <summary>
        /// ES: indica si en el resultado final se incluirá el Nonce como parte de los datos o no: 
        /// false => datos originales, true => datos incluyendo el Nonce en la posición indicada en NoncePosition
        /// Por defecto: true
        /// </summary>
        public bool NonceInData { get; set; }

        /// <summary>
        /// ES: indica si el minado empezará a probar desde Nonce = 0 (o una serie de bytes a cero), de lo contrario
        /// se empezará con un valor aleatorio
        /// Por defecto: false
        /// </summary>
        public bool NonceFromZero { get; set; }

        /*// <summary>
        /// (to be implemented on next publication)
        /// </summary>
        public bool FlexNonce { get; set; }
        */

        /// <summary>
        /// ES: Valor del requisito a alcanzar por el hash calculado
        /// Si Challenge es LessOrEqualThan, se incluirá un valor en bytes comparable al dato original. En este caso
        /// se puede usar el formato empaquetado similar a "Bits" en los bloques de Bitcoin.
        /// Si Challenge es StartsWith, se incluirá un valor con los primeros bytes que deben coincidir al principio
        /// del hash resultante, no necesariamente ceros.
        /// </summary>
        public byte[] ChallengeValue { get; set; }

        /// <summary>
        /// ES: función de comparación entre el hash calculado y el requisito que debe cumplir
        /// LessOrEqualThan es similar al que se aplica en Bitcoin
        /// StartsWith busca una coincidencia al principio, que podría o no ser un número de ceros
        /// </summary>
        public MiningChallenge Challenge { get; set; }

        /// <summary>
        /// El listado de algoritmos Hash a calcular, que puede ser un listado cualquiera de algoritmos
        /// registrados en qrypu.Code.Crypto
        /// El equivalente en Bitcoin sería { CryptoHashName.Sha256, CryptoHashName.256 }
        /// </summary>
        public CryptoHashName[] HashRecipe { get; set; }

        public MiningConfig()
        {
            this.NoncePosition = MiningNoncePosition.Tail;
            this.NonceLength = 8;
            this.NonceInData = true;
            this.NonceFromZero = false;
            //this.FlexNonce = false;

            this.Challenge = MiningBytes.LessOrEqualThan;
            this.ChallengeValue = MiningBytes.Unpack(0x1D00FFFF);

            this.HashRecipe = new[] { CryptoHashName.Sha256 };
        }
    }
}