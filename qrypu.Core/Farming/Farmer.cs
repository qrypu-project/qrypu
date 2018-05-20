/*
 * (C) 2018 José Hurtado
 * 
 * ES: En qrypu se utiliza el término labrado en lugar de minado porque se pondrán todos
 * los mecanismos necesarios para evitar el trabajo de grandes centros de datos, buscando
 * un formato de colaboración similar a los pool de minería, donde todos aportan su
 * trabajo y siempre obtienen una recompenda por ello.
 * Licencia: para este archivo se aplica: https://opensource.org/licenses/MIT
 */
namespace qrypu.Core.Farming
{
    using qrypu.Core.Crypto;
    using System;
    using System.Diagnostics;

    /// <summary>
    /// ES: Clase de labrado por hash
    /// </summary>
    public static class Farmer
    {
        /// <summary>
        /// ES: Cálculo de Nonce
        /// </summary>
        /// <param name="data">ES: Datos a labrar</param>
        /// <param name="config">ES: Configuración de labrado</param>
        /// <returns>ES: Resultado incluyendo Nonce y estadísticas</returns>
        public static FarmingResult Compute(byte[] data, FarmingConfig config)
        {
            var watch = Stopwatch.StartNew();

            var challenge = config.Challenge ?? FarmingBytes.LessOrEqualThan;
            var hashRecipe = new HashRecipe(config.HashRecipe);
            byte[] hash;

            // Nonce initilization
            var nonceLength = config.NonceLength;
            byte[] nonce;
            if (config.NonceFromZero)
                nonce = new byte[nonceLength];  // ES: inicia en 0
            else
                nonce = FarmingBytes.SeedNonce(nonceLength);   // ES: inicia en un valor aleatorio

            // Nonce position
            int noncePosition;
            if (config.NoncePosition == FarmingNoncePosition.Head)
                noncePosition = data.ChangeHead(nonce);
            else
                noncePosition = data.ChangeTail(nonce);

            // Compute hash
            UInt64 hashCount = 0;
            do
            {
                data.IncNonce(noncePosition, nonceLength);  // TODO: handle when returns false (cycle)
                hash = hashRecipe.ComputeHash(data);
                hashCount++;
            }
            while (!challenge(hash, config.ChallengeValue));
            watch.Stop();

            nonce = data.ExtractNonce(noncePosition, nonceLength);

            return new FarmingResult
            {
                Data = data,
                Nonce = nonce,
                Hash = hash,
                HashCount = hashCount,
                HashPerSecond = (hashCount * 1000.0F) / watch.ElapsedMilliseconds,
                FarmingTime = watch.ElapsedMilliseconds
            };
        }

        /// <summary>
        /// ES: Comprobación del Nonce. Calcula el Hash con el Nonce indicado y comprueba que coincide
        /// con el Hash propuesto
        /// </summary>
        /// <param name="data">ES: Datos origen del Hash</param>
        /// <param name="nonce">ES: Nonce propuesto</param>
        /// <param name="config">ES: Configuración de labrado</param>
        /// <returns>ES: Resultados incluyendo el Nonce y Hash recalculados</returns>
        public static FarmingResult CheckNonce(byte[] data, byte[] nonce, FarmingConfig config)
        {
            var challenge = config.Challenge ?? FarmingBytes.LessOrEqualThan;
            var hasherStack = new HashRecipe(config.HashRecipe);

            byte[] hash = hasherStack.ComputeHash(data);

            var result = new FarmingResult
            {
                Data = data,
                Nonce = nonce,
                Hash = hash,
                HashCount = 0
            };

            if (challenge(hash, config.ChallengeValue))
            {
                int noncePosition;

                if (config.NoncePosition == FarmingNoncePosition.Head)
                    noncePosition = 0;
                else
                    noncePosition = data.Length - config.NonceLength;

                var dataNonce = data.ExtractNonce(noncePosition, config.NonceLength);
                result.Nonce = dataNonce;

                if (FarmingBytes.NoncesAreEqual(dataNonce, nonce))
                    result.HashCount = 1;
            }

            return result;
        }
    }
}