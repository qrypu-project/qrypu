namespace qrypu.Core.Mining
{
    using qrypu.Core.Crypto;
    using System;
    using System.Diagnostics;

    /// <summary>
    /// ES: Clase de minado por hash
    /// </summary>
    public static class Miner
    {
        /// <summary>
        /// ES: Cálculo de Nonce
        /// </summary>
        /// <param name="data">ES: Datos a minar</param>
        /// <param name="config">ES: Configuración de minado</param>
        /// <returns>ES: Resultado incluyendo Nonce y estadísticas</returns>
        public static MiningResult Compute(byte[] data, MiningConfig config)
        {
            var watch = Stopwatch.StartNew();

            var challenge = config.Challenge ?? MiningBytes.LessOrEqualThan;
            var hashRecipe = new HashRecipe(config.HashRecipe);
            byte[] hash;

            // Nonce initilization
            var nonceLength = config.NonceLength;
            byte[] nonce;
            if (config.NonceFromZero)
                nonce = new byte[nonceLength];  // ES: inicia en 0
            else
                nonce = MiningBytes.SeedNonce(nonceLength);   // ES: inicia en un valor aleatorio

            // Nonce position
            int noncePosition;
            if (config.NoncePosition == MiningNoncePosition.Head)
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

            return new MiningResult
            {
                Data = data,
                Nonce = nonce,
                Hash = hash,
                HashCount = hashCount,
                HashPerSecond = (hashCount * 1000.0F) / watch.ElapsedMilliseconds,
                MiningTime = watch.ElapsedMilliseconds
            };
        }

        /// <summary>
        /// ES: Comprobación del Nonce. Calcula el Hash con el Nonce indicado y comprueba que coincide
        /// con el Hash propuesto
        /// </summary>
        /// <param name="data">ES: Datos origen del Hash</param>
        /// <param name="nonce">ES: Nonce propuesto</param>
        /// <param name="config">ES: Configuración de minado</param>
        /// <returns>ES: Resultados incluyendo el Nonce y Hash recalculados</returns>
        public static MiningResult CheckNonce(byte[] data, byte[] nonce, MiningConfig config)
        {
            var challenge = config.Challenge ?? MiningBytes.LessOrEqualThan;
            var hasherStack = new HashRecipe(config.HashRecipe);

            byte[] hash = hasherStack.ComputeHash(data);

            var result = new MiningResult
            {
                Data = data,
                Nonce = nonce,
                Hash = hash,
                HashCount = 0
            };

            if (challenge(hash, config.ChallengeValue))
            {
                int noncePosition;

                if (config.NoncePosition == MiningNoncePosition.Head)
                    noncePosition = 0;
                else
                    noncePosition = data.Length - config.NonceLength;

                var dataNonce = data.ExtractNonce(noncePosition, config.NonceLength);
                result.Nonce = dataNonce;

                if (MiningBytes.NoncesAreEqual(dataNonce, nonce))
                    result.HashCount = 1;
            }

            return result;
        }
    }
}