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

        public static byte[] CyrptoSecretBoxOpenNonce(byte[] ciphertext, byte[] secret_key)
        {
            return NaClBurstBackend.CyrptoSecretBoxOpenNonce(ciphertext, secret_key);
        }

        public static byte[] CyrptoSecretBoxNonce(byte[] message, byte[] secret_key)
        {
            return NaClBurstBackend.CyrptoSecretBoxNonce(message, secret_key);
        }

        public static byte[] CyrptoSecretBox(byte[] message, byte[] nonce, byte[] secret_key)
        {
            return NaClBurstBackend.CyrptoSecretBox(message, nonce, secret_key);
        }

        public static byte[] CyrptoSecretBoxOpen(byte[] payload, byte[] nonce, byte[] secret_key)
        {
            return NaClBurstBackend.CyrptoSecretBoxOpen(payload, nonce, secret_key);
        }

        public static byte[] CyrptoBoxBeforenm(byte[] public_key, byte[] secret_key)
        {
            return NaClBurstBackend.CyrptoBoxBeforenm(public_key, secret_key);
        }

        public static byte[] CyrptoBoxKeypair(byte[] secret_key)
        {
            return NaClBurstBackend.CyrptoBoxKeypair(secret_key);
        }
    }
}
