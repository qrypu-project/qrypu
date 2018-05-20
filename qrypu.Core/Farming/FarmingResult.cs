/*
 * (C) 2018 José Hurtado
 * 
 * ES: Contiene los resultados del proceso de labrado
 * 
 * Licencia: para este archivo se aplica: https://opensource.org/licenses/MIT
 */
namespace qrypu.Core.Farming
{
    using System;

    /// <summary>
    /// ES: Resultado de labrado
    /// </summary>
    public class FarmingResult
    {
        /// <summary>
        /// ES: datos a los que se calcula el hash
        /// Si en la configuración FarmingConfig indica NonceInData=true, Data contiene el Nonce
        /// en la posición indicada en NoncePosition.
        /// </summary>
        public byte[] Data { get; set; }

        /// <summary>
        /// ES: Nonce calculado en el labrado
        /// </summary>
        public byte[] Nonce { get; set; }

        /// <summary>
        /// ES: Hash hallado que cumple con los requisitos de Chanllenge y ChallengeValue
        /// </summary>
        public byte[] Hash { get; set; }

        /// <summary>
        /// ES: Número de hashes calculados hasta hallar el Nonce
        /// </summary>
        public UInt64 HashCount { get; set; }

        /// <summary>
        /// ES: Media de hash calculados por segundo
        /// </summary>
        public float HashPerSecond { get; set; }

        /// <summary>
        /// ES: Tiempo trasncurrido durante el labrado
        /// </summary>
        public long FarmingTime { get; set; }
    }
}