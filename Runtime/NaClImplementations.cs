using System;
using System.Diagnostics;
using Unity.Burst;
using Unity.Collections.LowLevel.Unsafe;
using Unity.Jobs;

namespace NaCl
{
    internal static class NaClConstants
    {
        internal const int SecretKeyBytes = 32;
        internal const int PublicKeyBytes = 32;
        internal const int SharedKeyBytes = 32;
        internal const int NonceBytes = 24;
        internal const int NoncePrefixBytes = 8;
        internal const int SecretBoxPayloadOverhead = 16;
        internal const int PacketOverhead = NoncePrefixBytes + SecretBoxPayloadOverhead;
    }

    internal static class NaClInputValidation
    {
        internal static bool IsValidSecretBoxEncryptInput(byte[] message, byte[] secretKey)
        {
            return message != null &&
                   secretKey != null &&
                   secretKey.Length == NaClConstants.SecretKeyBytes;
        }

        internal static bool IsValidSecretBoxDecryptInput(byte[] ciphertext, byte[] secretKey)
        {
            return ciphertext != null &&
                   ciphertext.Length >= NaClConstants.PacketOverhead &&
                   secretKey != null &&
                   secretKey.Length == NaClConstants.SecretKeyBytes;
        }

        internal static bool IsValidBeforenmInput(byte[] publicKey, byte[] secretKey)
        {
            return publicKey != null &&
                   publicKey.Length == NaClConstants.PublicKeyBytes &&
                   secretKey != null &&
                   secretKey.Length == NaClConstants.SecretKeyBytes;
        }

        internal static bool IsValidSecretBoxEncryptWithNonceInput(byte[] message, byte[] nonce, byte[] secretKey)
        {
            return message != null &&
                   nonce != null &&
                   nonce.Length == NaClConstants.NonceBytes &&
                   secretKey != null &&
                   secretKey.Length == NaClConstants.SecretKeyBytes;
        }

        internal static bool IsValidSecretBoxDecryptWithNonceInput(byte[] payload, byte[] nonce, byte[] secretKey)
        {
            return payload != null &&
                   payload.Length >= NaClConstants.SecretBoxPayloadOverhead &&
                   nonce != null &&
                   nonce.Length == NaClConstants.NonceBytes &&
                   secretKey != null &&
                   secretKey.Length == NaClConstants.SecretKeyBytes;
        }

        internal static bool IsValidKeypairInput(byte[] secretKey)
        {
            return secretKey != null &&
                   secretKey.Length == NaClConstants.SecretKeyBytes;
        }
    }

    internal static class NaClNonceGenerator
    {
        [ThreadStatic]
        private static ulong _state;

        internal static void FillNoncePrefix(Span<byte> noncePrefix)
        {
            if (noncePrefix.Length != NaClConstants.NoncePrefixBytes)
            {
                throw new ArgumentException($"nonce prefix must be {NaClConstants.NoncePrefixBytes} bytes", nameof(noncePrefix));
            }

            FillBytes(noncePrefix);
        }

        internal static void FillBytes(Span<byte> output)
        {
            var offset = 0;
            while (offset < output.Length)
            {
                var value = NextUInt64();
                var remaining = output.Length - offset;
                var chunk = remaining < 8 ? remaining : 8;

                for (var i = 0; i < chunk; ++i)
                {
                    output[offset + i] = (byte)(value >> (i * 8));
                }

                offset += chunk;
            }
        }

        private static ulong NextUInt64()
        {
            var s = _state;
            if (s == 0)
            {
                var timestamp = (ulong)Stopwatch.GetTimestamp();
                var threadId = (ulong)Environment.CurrentManagedThreadId;
                s = timestamp ^ (threadId * 0x9E3779B97F4A7C15UL);
                if (s == 0)
                {
                    s = 0xA5A5A5A5A5A5A5A5UL;
                }
            }

            // xorshift64*
            s ^= s >> 12;
            s ^= s << 25;
            s ^= s >> 27;
            _state = s;

            return s * 2685821657736338717UL;
        }
    }

    internal static unsafe class NaClBurstBackend
    {
        private static readonly bool _useBurstFunctions = BurstCompiler.IsEnabled;

        internal static void Preflight()
        {
            if (!_useBurstFunctions)
            {
                return;
            }

            var message = new byte[1];
            var key = new byte[NaClConstants.SecretKeyBytes];
            var noncePrefix = new byte[NaClConstants.NoncePrefixBytes];
            var ciphertext = new byte[NaClConstants.PacketOverhead + 1];
            var nonce = new byte[NaClConstants.NonceBytes];
            var payload = new byte[NaClConstants.SecretBoxPayloadOverhead + 1];
            var publicKey = new byte[NaClConstants.PublicKeyBytes];
            var secretKey = new byte[NaClConstants.SecretKeyBytes];

            _ = CyrptoSecretBoxNonceWithNoncePrefix(message, key, noncePrefix);
            _ = CyrptoSecretBoxOpenNonce(ciphertext, key);
            _ = CyrptoSecretBox(message, nonce, key);
            _ = CyrptoSecretBoxOpen(payload, nonce, key);
            _ = CyrptoBoxKeypair(secretKey);
            _ = CyrptoBoxBeforenm(publicKey, secretKey);
        }

        internal static byte[] CyrptoSecretBoxNonce(byte[] message, byte[] secretKey)
        {
            if (!NaClInputValidation.IsValidSecretBoxEncryptInput(message, secretKey))
            {
                return null;
            }

            Span<byte> noncePrefix = stackalloc byte[NaClConstants.NoncePrefixBytes];
            NaClNonceGenerator.FillNoncePrefix(noncePrefix);
            return CyrptoSecretBoxNonceWithNoncePrefix(message, secretKey, noncePrefix);
        }

        internal static byte[] CyrptoSecretBoxNonceWithNoncePrefix(byte[] message, byte[] secretKey, ReadOnlySpan<byte> noncePrefix)
        {
            if (!NaClInputValidation.IsValidSecretBoxEncryptInput(message, secretKey) ||
                noncePrefix.Length != NaClConstants.NoncePrefixBytes)
            {
                return null;
            }

            try
            {
                var output = new byte[message.Length + NaClConstants.PacketOverhead];
                var result = 0;

                fixed (byte* outputPtr = output)
                fixed (byte* messagePtr = message)
                fixed (byte* secretKeyPtr = secretKey)
                fixed (byte* noncePrefixPtr = noncePrefix)
                {
                    var resultPtr = &result;
                    var job = new EncryptJob
                    {
                        Output = outputPtr,
                        Message = messagePtr,
                        MessageLength = message.Length,
                        SecretKey = secretKeyPtr,
                        NoncePrefix = noncePrefixPtr,
                        Result = resultPtr,
                    };
                    job.Run();
                }

                return result == 0 ? output : null;
            }
            catch
            {
                return null;
            }
        }

        internal static byte[] CyrptoSecretBoxOpenNonce(byte[] ciphertext, byte[] secretKey)
        {
            if (!NaClInputValidation.IsValidSecretBoxDecryptInput(ciphertext, secretKey))
            {
                return null;
            }

            try
            {
                var message = new byte[ciphertext.Length - NaClConstants.PacketOverhead];
                var result = 0;

                fixed (byte* messagePtr = message)
                fixed (byte* ciphertextPtr = ciphertext)
                fixed (byte* secretKeyPtr = secretKey)
                {
                    var resultPtr = &result;
                    var job = new DecryptJob
                    {
                        Message = messagePtr,
                        Ciphertext = ciphertextPtr,
                        CiphertextLength = ciphertext.Length,
                        SecretKey = secretKeyPtr,
                        Result = resultPtr,
                    };
                    job.Run();
                }

                return result == 0 ? message : null;
            }
            catch
            {
                return null;
            }
        }

        internal static byte[] CyrptoSecretBox(byte[] message, byte[] nonce, byte[] secretKey)
        {
            if (!NaClInputValidation.IsValidSecretBoxEncryptWithNonceInput(message, nonce, secretKey))
            {
                return null;
            }

            try
            {
                var payload = new byte[message.Length + NaClConstants.SecretBoxPayloadOverhead];
                var result = 0;

                fixed (byte* payloadPtr = payload)
                fixed (byte* messagePtr = message)
                fixed (byte* noncePtr = nonce)
                fixed (byte* secretKeyPtr = secretKey)
                {
                    var resultPtr = &result;
                    var job = new SecretBoxEncryptJob
                    {
                        OutputPayload = payloadPtr,
                        Message = messagePtr,
                        MessageLength = message.Length,
                        Nonce = noncePtr,
                        SecretKey = secretKeyPtr,
                        Result = resultPtr,
                    };
                    job.Run();
                }

                return result == 0 ? payload : null;
            }
            catch
            {
                return null;
            }
        }

        internal static byte[] CyrptoSecretBoxOpen(byte[] payload, byte[] nonce, byte[] secretKey)
        {
            if (!NaClInputValidation.IsValidSecretBoxDecryptWithNonceInput(payload, nonce, secretKey))
            {
                return null;
            }

            try
            {
                var message = new byte[payload.Length - NaClConstants.SecretBoxPayloadOverhead];
                var result = 0;

                fixed (byte* messagePtr = message)
                fixed (byte* payloadPtr = payload)
                fixed (byte* noncePtr = nonce)
                fixed (byte* secretKeyPtr = secretKey)
                {
                    var resultPtr = &result;
                    var job = new SecretBoxDecryptJob
                    {
                        Message = messagePtr,
                        Payload = payloadPtr,
                        PayloadLength = payload.Length,
                        Nonce = noncePtr,
                        SecretKey = secretKeyPtr,
                        Result = resultPtr,
                    };
                    job.Run();
                }

                return result == 0 ? message : null;
            }
            catch
            {
                return null;
            }
        }

        internal static byte[] CyrptoBoxKeypair(byte[] secretKey)
        {
            if (!NaClInputValidation.IsValidKeypairInput(secretKey))
            {
                return null;
            }

            try
            {
                NaClNonceGenerator.FillBytes(secretKey);

                var publicKey = new byte[NaClConstants.PublicKeyBytes];
                var result = 0;

                fixed (byte* publicKeyPtr = publicKey)
                fixed (byte* secretKeyPtr = secretKey)
                {
                    var resultPtr = &result;
                    var job = new KeypairJob
                    {
                        PublicKey = publicKeyPtr,
                        SecretKey = secretKeyPtr,
                        Result = resultPtr,
                    };
                    job.Run();
                }

                return result == 0 ? publicKey : null;
            }
            catch
            {
                return null;
            }
        }

        internal static byte[] CyrptoBoxBeforenm(byte[] publicKey, byte[] secretKey)
        {
            if (!NaClInputValidation.IsValidBeforenmInput(publicKey, secretKey))
            {
                return null;
            }

            try
            {
                var shared = new byte[NaClConstants.SharedKeyBytes];
                var result = 0;

                fixed (byte* sharedPtr = shared)
                fixed (byte* publicKeyPtr = publicKey)
                fixed (byte* secretKeyPtr = secretKey)
                {
                    var resultPtr = &result;
                    var job = new BeforenmJob
                    {
                        SharedKey = sharedPtr,
                        PublicKey = publicKeyPtr,
                        SecretKey = secretKeyPtr,
                        Result = resultPtr,
                    };
                    job.Run();
                }

                return result == 0 ? shared : null;
            }
            catch
            {
                return null;
            }
        }

        [BurstCompile(CompileSynchronously = true, DisableSafetyChecks = true)]
        private unsafe struct EncryptJob : IJob
        {
            [NativeDisableUnsafePtrRestriction] public byte* Output;
            [NativeDisableUnsafePtrRestriction] public byte* Message;
            [NativeDisableUnsafePtrRestriction] public byte* SecretKey;
            [NativeDisableUnsafePtrRestriction] public byte* NoncePrefix;
            [NativeDisableUnsafePtrRestriction] public int* Result;
            public int MessageLength;

            public void Execute()
            {
                for (var i = 0; i < NaClConstants.NoncePrefixBytes; ++i)
                {
                    Output[i] = NoncePrefix[i];
                }

                byte* nonce = stackalloc byte[NaClConstants.NonceBytes];
                for (var i = 0; i < NaClConstants.NonceBytes; ++i)
                {
                    nonce[i] = 0;
                }
                for (var i = 0; i < NaClConstants.NoncePrefixBytes; ++i)
                {
                    nonce[i] = NoncePrefix[i];
                }

                Result[0] = NaClBurstCore.CryptoSecretboxEasy(
                    Output + NaClConstants.NoncePrefixBytes,
                    Message,
                    MessageLength,
                    nonce,
                    SecretKey);
            }
        }

        [BurstCompile(CompileSynchronously = true, DisableSafetyChecks = true)]
        private unsafe struct DecryptJob : IJob
        {
            [NativeDisableUnsafePtrRestriction] public byte* Message;
            [NativeDisableUnsafePtrRestriction] public byte* Ciphertext;
            [NativeDisableUnsafePtrRestriction] public byte* SecretKey;
            [NativeDisableUnsafePtrRestriction] public int* Result;
            public int CiphertextLength;

            public void Execute()
            {
                byte* nonce = stackalloc byte[NaClConstants.NonceBytes];
                for (var i = 0; i < NaClConstants.NonceBytes; ++i)
                {
                    nonce[i] = 0;
                }
                for (var i = 0; i < NaClConstants.NoncePrefixBytes; ++i)
                {
                    nonce[i] = Ciphertext[i];
                }

                Result[0] = NaClBurstCore.CryptoSecretboxOpenEasy(
                    Message,
                    Ciphertext + NaClConstants.NoncePrefixBytes,
                    CiphertextLength - NaClConstants.NoncePrefixBytes,
                    nonce,
                    SecretKey);
            }
        }

        [BurstCompile(CompileSynchronously = true, DisableSafetyChecks = true)]
        private unsafe struct SecretBoxEncryptJob : IJob
        {
            [NativeDisableUnsafePtrRestriction] public byte* OutputPayload;
            [NativeDisableUnsafePtrRestriction] public byte* Message;
            [NativeDisableUnsafePtrRestriction] public byte* Nonce;
            [NativeDisableUnsafePtrRestriction] public byte* SecretKey;
            [NativeDisableUnsafePtrRestriction] public int* Result;
            public int MessageLength;

            public void Execute()
            {
                Result[0] = NaClBurstCore.CryptoSecretboxEasy(
                    OutputPayload,
                    Message,
                    MessageLength,
                    Nonce,
                    SecretKey);
            }
        }

        [BurstCompile(CompileSynchronously = true, DisableSafetyChecks = true)]
        private unsafe struct SecretBoxDecryptJob : IJob
        {
            [NativeDisableUnsafePtrRestriction] public byte* Message;
            [NativeDisableUnsafePtrRestriction] public byte* Payload;
            [NativeDisableUnsafePtrRestriction] public byte* Nonce;
            [NativeDisableUnsafePtrRestriction] public byte* SecretKey;
            [NativeDisableUnsafePtrRestriction] public int* Result;
            public int PayloadLength;

            public void Execute()
            {
                Result[0] = NaClBurstCore.CryptoSecretboxOpenEasy(
                    Message,
                    Payload,
                    PayloadLength,
                    Nonce,
                    SecretKey);
            }
        }

        [BurstCompile(CompileSynchronously = true, DisableSafetyChecks = true)]
        private unsafe struct KeypairJob : IJob
        {
            [NativeDisableUnsafePtrRestriction] public byte* PublicKey;
            [NativeDisableUnsafePtrRestriction] public byte* SecretKey;
            [NativeDisableUnsafePtrRestriction] public int* Result;

            public void Execute()
            {
                Result[0] = NaClBurstCore.CryptoScalarmultBase(PublicKey, SecretKey);
            }
        }

        [BurstCompile(CompileSynchronously = true, DisableSafetyChecks = true)]
        private unsafe struct BeforenmJob : IJob
        {
            [NativeDisableUnsafePtrRestriction] public byte* SharedKey;
            [NativeDisableUnsafePtrRestriction] public byte* PublicKey;
            [NativeDisableUnsafePtrRestriction] public byte* SecretKey;
            [NativeDisableUnsafePtrRestriction] public int* Result;

            public void Execute()
            {
                Result[0] = NaClBurstCore.CryptoBoxBeforenm(SharedKey, PublicKey, SecretKey);
            }
        }
    }

    internal static unsafe class NaClBurstCore
    {
        private const uint SigmaWord0 = 0x61707865u;
        private const uint SigmaWord1 = 0x3320646eu;
        private const uint SigmaWord2 = 0x79622d32u;
        private const uint SigmaWord3 = 0x6b206574u;

        internal static int CryptoSecretboxEasy(byte* outputPayload, byte* message, int messageLength, byte* nonce, byte* secretKey)
        {
            if (messageLength < 0)
            {
                return -1;
            }

            byte* authKey = stackalloc byte[32];
            CryptoStream(authKey, 32, nonce, secretKey);
            CryptoStreamXorOffset32(outputPayload + 16, message, (ulong)messageLength, nonce, secretKey);
            CryptoOnetimeauth(outputPayload, outputPayload + 16, (ulong)messageLength, authKey);
            return 0;
        }

        internal static int CryptoSecretboxOpenEasy(byte* outputMessage, byte* payload, int payloadLength, byte* nonce, byte* secretKey)
        {
            if (payloadLength < 16)
            {
                return -1;
            }

            var messageLength = payloadLength - 16;
            byte* authKey = stackalloc byte[32];
            CryptoStream(authKey, 32, nonce, secretKey);
            if (CryptoOnetimeauthVerify(payload, payload + 16, (ulong)messageLength, authKey) != 0)
            {
                return -1;
            }

            CryptoStreamXorOffset32(outputMessage, payload + 16, (ulong)messageLength, nonce, secretKey);
            return 0;
        }

        internal static int CryptoBoxBeforenm(byte* sharedKey, byte* publicKey, byte* secretKey)
        {
            byte* s = stackalloc byte[32];
            byte* zero = stackalloc byte[16];
            for (var i = 0; i < 16; ++i)
            {
                zero[i] = 0;
            }

            CryptoScalarmult(s, secretKey, publicKey);
            return CryptoCoreHsalsa20(sharedKey, zero, s);
        }

        private static uint L32(uint x, int c)
        {
            return (x << c) | (x >> (32 - c));
        }

        private static uint Ld32(byte* x)
        {
            uint u = x[3];
            u = (u << 8) | x[2];
            u = (u << 8) | x[1];
            return (u << 8) | x[0];
        }

        private static void St32(byte* x, uint u)
        {
            for (var i = 0; i < 4; ++i)
            {
                x[i] = (byte)u;
                u >>= 8;
            }
        }

        private static int Vn(byte* x, byte* y, int n)
        {
            uint d = 0;
            for (var i = 0; i < n; ++i)
            {
                d |= (uint)(x[i] ^ y[i]);
            }

            return (int)((1u & ((d - 1u) >> 8)) - 1u);
        }

        private static int CryptoVerify16(byte* x, byte* y)
        {
            return Vn(x, y, 16);
        }

        private static int CryptoVerify32(byte* x, byte* y)
        {
            return Vn(x, y, 32);
        }

        private static void Core(byte* output, byte* input, byte* key, int hsalsa)
        {
            uint* w = stackalloc uint[16];
            uint* x = stackalloc uint[16];
            uint* y = stackalloc uint[16];
            uint* t = stackalloc uint[4];

            for (var i = 0; i < 4; ++i)
            {
                var sigmaWord = i == 0 ? SigmaWord0 : i == 1 ? SigmaWord1 : i == 2 ? SigmaWord2 : SigmaWord3;
                x[5 * i] = sigmaWord;
                x[1 + i] = Ld32(key + 4 * i);
                x[6 + i] = Ld32(input + 4 * i);
                x[11 + i] = Ld32(key + 16 + 4 * i);
            }

            for (var i = 0; i < 16; ++i)
            {
                y[i] = x[i];
            }

            for (var i = 0; i < 20; ++i)
            {
                for (var j = 0; j < 4; ++j)
                {
                    for (var m = 0; m < 4; ++m)
                    {
                        t[m] = x[(5 * j + 4 * m) % 16];
                    }

                    t[1] ^= L32(t[0] + t[3], 7);
                    t[2] ^= L32(t[1] + t[0], 9);
                    t[3] ^= L32(t[2] + t[1], 13);
                    t[0] ^= L32(t[3] + t[2], 18);

                    for (var m = 0; m < 4; ++m)
                    {
                        w[4 * j + (j + m) % 4] = t[m];
                    }
                }

                for (var m = 0; m < 16; ++m)
                {
                    x[m] = w[m];
                }
            }

            if (hsalsa != 0)
            {
                for (var i = 0; i < 16; ++i)
                {
                    x[i] += y[i];
                }

                for (var i = 0; i < 4; ++i)
                {
                    var sigmaWord = i == 0 ? SigmaWord0 : i == 1 ? SigmaWord1 : i == 2 ? SigmaWord2 : SigmaWord3;
                    x[5 * i] -= sigmaWord;
                    x[6 + i] -= Ld32(input + 4 * i);
                }

                for (var i = 0; i < 4; ++i)
                {
                    St32(output + 4 * i, x[5 * i]);
                    St32(output + 16 + 4 * i, x[6 + i]);
                }
            }
            else
            {
                for (var i = 0; i < 16; ++i)
                {
                    St32(output + 4 * i, x[i] + y[i]);
                }
            }
        }

        private static int CryptoCoreSalsa20(byte* output, byte* input, byte* key)
        {
            Core(output, input, key, 0);
            return 0;
        }

        private static int CryptoCoreHsalsa20(byte* output, byte* input, byte* key)
        {
            Core(output, input, key, 1);
            return 0;
        }

        private static int CryptoStreamSalsa20Xor(byte* c, byte* m, ulong b, byte* n, byte* k)
        {
            byte* z = stackalloc byte[16];
            byte* x = stackalloc byte[64];

            if (b == 0)
            {
                return 0;
            }

            for (var i = 0; i < 16; ++i)
            {
                z[i] = 0;
            }
            for (var i = 0; i < 8; ++i)
            {
                z[i] = n[i];
            }

            while (b >= 64)
            {
                CryptoCoreSalsa20(x, z, k);
                for (var i = 0; i < 64; ++i)
                {
                    c[i] = (byte)((m != null ? m[i] : 0) ^ x[i]);
                }

                uint u = 1;
                for (var i = 8; i < 16; ++i)
                {
                    u += z[i];
                    z[i] = (byte)u;
                    u >>= 8;
                }

                b -= 64;
                c += 64;
                if (m != null)
                {
                    m += 64;
                }
            }

            if (b > 0)
            {
                CryptoCoreSalsa20(x, z, k);
                for (ulong i = 0; i < b; ++i)
                {
                    c[i] = (byte)((m != null ? m[i] : 0) ^ x[i]);
                }
            }

            return 0;
        }

        private static int CryptoStream(byte* c, ulong d, byte* n, byte* k)
        {
            byte* s = stackalloc byte[32];
            CryptoCoreHsalsa20(s, n, k);
            return CryptoStreamSalsa20Xor(c, null, d, n + 16, s);
        }

        private static void CryptoStreamXorOffset32(byte* output, byte* input, ulong length, byte* nonce, byte* key)
        {
            byte* s = stackalloc byte[32];
            byte* z = stackalloc byte[16];
            byte* block = stackalloc byte[64];

            CryptoCoreHsalsa20(s, nonce, key);

            for (var i = 0; i < 16; ++i)
            {
                z[i] = 0;
            }
            for (var i = 0; i < 8; ++i)
            {
                z[i] = nonce[16 + i];
            }

            var streamOffset = 32ul;
            var produced = 0ul;
            while (produced < length)
            {
                CryptoCoreSalsa20(block, z, s);

                var blockStart = 0ul;
                if (streamOffset >= 64)
                {
                    streamOffset -= 64;
                }
                else
                {
                    blockStart = streamOffset;
                    var blockLength = 64ul - blockStart;
                    var remaining = length - produced;
                    if (blockLength > remaining)
                    {
                        blockLength = remaining;
                    }

                    for (ulong i = 0; i < blockLength; ++i)
                    {
                        output[produced + i] = (byte)(input[produced + i] ^ block[blockStart + i]);
                    }

                    produced += blockLength;
                    streamOffset = 0;
                }

                uint u = 1;
                for (var i = 8; i < 16; ++i)
                {
                    u += z[i];
                    z[i] = (byte)u;
                    u >>= 8;
                }
            }
        }

        private static void Add1305(uint* h, uint* c)
        {
            uint u = 0;
            for (var j = 0; j < 17; ++j)
            {
                u += h[j] + c[j];
                h[j] = u & 255;
                u >>= 8;
            }
        }

        private static int CryptoOnetimeauth(byte* output, byte* m, ulong n, byte* k)
        {
            uint* x = stackalloc uint[17];
            uint* r = stackalloc uint[17];
            uint* h = stackalloc uint[17];
            uint* c = stackalloc uint[17];
            uint* g = stackalloc uint[17];
            uint* minusp = stackalloc uint[17];

            minusp[0] = 5;
            for (var i = 1; i < 16; ++i)
            {
                minusp[i] = 0;
            }
            minusp[16] = 252;

            for (var j = 0; j < 17; ++j)
            {
                r[j] = 0;
                h[j] = 0;
            }
            for (var j = 0; j < 16; ++j)
            {
                r[j] = k[j];
            }

            r[3] &= 15;
            r[4] &= 252;
            r[7] &= 15;
            r[8] &= 252;
            r[11] &= 15;
            r[12] &= 252;
            r[15] &= 15;

            while (n > 0)
            {
                for (var j = 0; j < 17; ++j)
                {
                    c[j] = 0;
                }

                var jRead = 0;
                while (jRead < 16 && (ulong)jRead < n)
                {
                    c[jRead] = m[jRead];
                    ++jRead;
                }

                c[jRead] = 1;
                m += jRead;
                n -= (ulong)jRead;

                Add1305(h, c);

                for (var i = 0; i < 17; ++i)
                {
                    x[i] = 0;
                    for (var j = 0; j < 17; ++j)
                    {
                        x[i] += h[j] * (uint)(j <= i ? r[i - j] : 320 * r[i + 17 - j]);
                    }
                }

                for (var i = 0; i < 17; ++i)
                {
                    h[i] = x[i];
                }

                uint u = 0;
                for (var j = 0; j < 16; ++j)
                {
                    u += h[j];
                    h[j] = u & 255;
                    u >>= 8;
                }

                u += h[16];
                h[16] = u & 3;
                u = 5 * (u >> 2);

                for (var j = 0; j < 16; ++j)
                {
                    u += h[j];
                    h[j] = u & 255;
                    u >>= 8;
                }

                u += h[16];
                h[16] = u;
            }

            for (var j = 0; j < 17; ++j)
            {
                g[j] = h[j];
            }

            Add1305(h, minusp);
            var s = (uint)-(int)(h[16] >> 7);
            for (var j = 0; j < 17; ++j)
            {
                h[j] ^= s & (g[j] ^ h[j]);
            }

            for (var j = 0; j < 16; ++j)
            {
                c[j] = k[j + 16];
            }
            c[16] = 0;
            Add1305(h, c);

            for (var j = 0; j < 16; ++j)
            {
                output[j] = (byte)h[j];
            }

            return 0;
        }

        private static int CryptoOnetimeauthVerify(byte* h, byte* m, ulong n, byte* k)
        {
            byte* x = stackalloc byte[16];
            CryptoOnetimeauth(x, m, n, k);
            return CryptoVerify16(h, x);
        }

        private static void Set25519(long* r, long* a)
        {
            for (var i = 0; i < 16; ++i)
            {
                r[i] = a[i];
            }
        }

        private static void Car25519(long* o)
        {
            for (var i = 0; i < 16; ++i)
            {
                o[i] += 1L << 16;
                var c = o[i] >> 16;
                var next = i < 15 ? i + 1 : 0;
                o[next] += c - 1 + (i == 15 ? 37 * (c - 1) : 0);
                o[i] -= c << 16;
            }
        }

        private static void Sel25519(long* p, long* q, int b)
        {
            var c = ~(long)(b - 1);
            for (var i = 0; i < 16; ++i)
            {
                var t = c & (p[i] ^ q[i]);
                p[i] ^= t;
                q[i] ^= t;
            }
        }

        private static void Pack25519(byte* o, long* n)
        {
            long* m = stackalloc long[16];
            long* t = stackalloc long[16];

            for (var i = 0; i < 16; ++i)
            {
                t[i] = n[i];
            }

            Car25519(t);
            Car25519(t);
            Car25519(t);

            for (var j = 0; j < 2; ++j)
            {
                m[0] = t[0] - 0xffed;
                for (var i = 1; i < 15; ++i)
                {
                    m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
                    m[i - 1] &= 0xffff;
                }

                m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
                var b = (int)((m[15] >> 16) & 1);
                m[14] &= 0xffff;
                Sel25519(t, m, 1 - b);
            }

            for (var i = 0; i < 16; ++i)
            {
                o[2 * i] = (byte)(t[i] & 0xff);
                o[2 * i + 1] = (byte)(t[i] >> 8);
            }
        }

        private static int Neq25519(long* a, long* b)
        {
            byte* c = stackalloc byte[32];
            byte* d = stackalloc byte[32];
            Pack25519(c, a);
            Pack25519(d, b);
            return CryptoVerify32(c, d);
        }

        private static byte Par25519(long* a)
        {
            byte* d = stackalloc byte[32];
            Pack25519(d, a);
            return (byte)(d[0] & 1);
        }

        private static void Unpack25519(long* o, byte* n)
        {
            for (var i = 0; i < 16; ++i)
            {
                o[i] = n[2 * i] + ((long)n[2 * i + 1] << 8);
            }
            o[15] &= 0x7fff;
        }

        private static void A(long* o, long* a, long* b)
        {
            for (var i = 0; i < 16; ++i)
            {
                o[i] = a[i] + b[i];
            }
        }

        private static void Z(long* o, long* a, long* b)
        {
            for (var i = 0; i < 16; ++i)
            {
                o[i] = a[i] - b[i];
            }
        }

        private static void M(long* o, long* a, long* b)
        {
            long* t = stackalloc long[31];
            for (var i = 0; i < 31; ++i)
            {
                t[i] = 0;
            }

            for (var i = 0; i < 16; ++i)
            {
                for (var j = 0; j < 16; ++j)
                {
                    t[i + j] += a[i] * b[j];
                }
            }

            for (var i = 0; i < 15; ++i)
            {
                t[i] += 38 * t[i + 16];
            }

            for (var i = 0; i < 16; ++i)
            {
                o[i] = t[i];
            }

            Car25519(o);
            Car25519(o);
        }

        private static void S(long* o, long* a)
        {
            M(o, a, a);
        }

        private static void Inv25519(long* output, long* input)
        {
            long* c = stackalloc long[16];
            for (var a = 0; a < 16; ++a)
            {
                c[a] = input[a];
            }

            for (var a = 253; a >= 0; --a)
            {
                S(c, c);
                if (a != 2 && a != 4)
                {
                    M(c, c, input);
                }
            }

            for (var a = 0; a < 16; ++a)
            {
                output[a] = c[a];
            }
        }

        private static int CryptoScalarmult(byte* q, byte* n, byte* p)
        {
            byte* z = stackalloc byte[32];
            long* x = stackalloc long[80];
            long* a = stackalloc long[16];
            long* b = stackalloc long[16];
            long* c = stackalloc long[16];
            long* d = stackalloc long[16];
            long* e = stackalloc long[16];
            long* f = stackalloc long[16];
            long* c121665 = stackalloc long[16];

            c121665[0] = 0xDB41;
            c121665[1] = 1;
            for (var i = 2; i < 16; ++i)
            {
                c121665[i] = 0;
            }

            for (var i = 0; i < 31; ++i)
            {
                z[i] = n[i];
            }
            z[31] = (byte)((n[31] & 127) | 64);
            z[0] &= 248;

            Unpack25519(x, p);
            for (var i = 0; i < 16; ++i)
            {
                b[i] = x[i];
                d[i] = 0;
                a[i] = 0;
                c[i] = 0;
            }
            a[0] = 1;
            d[0] = 1;

            for (var i = 254; i >= 0; --i)
            {
                var r = (z[i >> 3] >> (i & 7)) & 1;
                Sel25519(a, b, r);
                Sel25519(c, d, r);
                A(e, a, c);
                Z(a, a, c);
                A(c, b, d);
                Z(b, b, d);
                S(d, e);
                S(f, a);
                M(a, c, a);
                M(c, b, e);
                A(e, a, c);
                Z(a, a, c);
                S(b, a);
                Z(c, d, f);
                M(a, c, c121665);
                A(a, a, d);
                M(c, c, a);
                M(a, d, f);
                M(d, b, x);
                S(b, e);
                Sel25519(a, b, r);
                Sel25519(c, d, r);
            }

            for (var i = 0; i < 16; ++i)
            {
                x[i + 16] = a[i];
                x[i + 32] = c[i];
                x[i + 48] = b[i];
                x[i + 64] = d[i];
            }

            Inv25519(x + 32, x + 32);
            M(x + 16, x + 16, x + 32);
            Pack25519(q, x + 16);
            return 0;
        }

        internal static int CryptoScalarmultBase(byte* q, byte* n)
        {
            byte* basePoint = stackalloc byte[32];
            for (var i = 0; i < 32; ++i)
            {
                basePoint[i] = 0;
            }

            basePoint[0] = 9;
            return CryptoScalarmult(q, n, basePoint);
        }
    }

}
