namespace NaCl
{
    public class NaCl
    {
        public const int BoxPublicKeyBytes = 32;
        public const int BoxSecretKeyBytes = 32;
        public const int BoxNonceBytes = 24;
        public const int BoxBeforenmBytes = 32;
        public const int SecretBoxKeyBytes = 32;
        public const int SecretBoxNonceBytes = 24;

        public static byte[] CryptoSecretBoxOpenNonce(byte[] ciphertext, byte[] secret_key)
        {
            return NaClBurstBackend.CryptoSecretBoxOpenNonce(ciphertext, secret_key);
        }

        public static byte[] CryptoSecretBoxNonce(byte[] message, byte[] secret_key)
        {
            return NaClBurstBackend.CryptoSecretBoxNonce(message, secret_key);
        }

        public static byte[] CryptoSecretBox(byte[] message, byte[] nonce, byte[] secret_key)
        {
            return NaClBurstBackend.CryptoSecretBox(message, nonce, secret_key);
        }

        public static byte[] CryptoSecretBoxOpen(byte[] payload, byte[] nonce, byte[] secret_key)
        {
            return NaClBurstBackend.CryptoSecretBoxOpen(payload, nonce, secret_key);
        }

        public static byte[] CryptoBoxBeforenm(byte[] public_key, byte[] secret_key)
        {
            return NaClBurstBackend.CryptoBoxBeforenm(public_key, secret_key);
        }

        public static byte[] CryptoBoxKeypair(byte[] secret_key)
        {
            return NaClBurstBackend.CryptoBoxKeypair(secret_key);
        }
    }
}
