using System.Text;
using FlatBuffers.Encryption;

Console.WriteLine("FlatBuffers WASI Encryption - C#/Wasmtime");
Console.WriteLine(new string('=', 50));

try
{
    using var em = new EncryptionModule();

    Console.WriteLine($"Module version: {em.Version()}");
    Console.WriteLine($"Crypto++ available: {em.HasCryptopp()}");
    Console.WriteLine();

    // Test AES encryption
    TestAesEncryption(em);

    // Test SHA-256
    TestSha256(em);

    // Test X25519
    TestX25519(em);

    // Test secp256k1
    TestSecp256k1(em);

    // Test P-256
    TestP256(em);

    // Test Ed25519
    TestEd25519(em);
}
catch (Exception e)
{
    Console.Error.WriteLine($"Error: {e.Message}");
    Console.WriteLine();
    Console.WriteLine("Build the WASM module first:");
    Console.WriteLine("  cmake --build build/wasm --target flatc_wasm_wasi");
}

static void TestAesEncryption(EncryptionModule em)
{
    Console.WriteLine("AES-256-CTR Encryption Test:");
    Console.WriteLine(new string('-', 30));

    var key = new byte[32];
    Array.Fill(key, (byte)0x42);
    var iv = new byte[16];
    Array.Fill(iv, (byte)0x24);

    var plaintext = "Hello, FlatBuffers WASI encryption from C#!"u8.ToArray();

    Console.WriteLine($"Plaintext: {Encoding.UTF8.GetString(plaintext)}");
    Console.WriteLine($"Key: {BytesToHex(key)}");
    Console.WriteLine($"IV: {BytesToHex(iv)}");

    var encrypted = em.Encrypt(key, iv, plaintext);
    Console.WriteLine($"Encrypted: {BytesToHex(encrypted)}");

    var decrypted = em.Decrypt(key, iv, encrypted);
    Console.WriteLine($"Decrypted: {Encoding.UTF8.GetString(decrypted)}");

    if (plaintext.SequenceEqual(decrypted))
        Console.WriteLine("OK Encryption/decryption successful!");
    else
        Console.WriteLine("FAIL Decryption mismatch!");

    Console.WriteLine();
}

static void TestSha256(EncryptionModule em)
{
    Console.WriteLine("SHA-256 Test:");
    Console.WriteLine(new string('-', 30));

    var hash = em.Sha256("hello"u8.ToArray());
    var hashHex = BytesToHex(hash);
    var expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    Console.WriteLine($"SHA256('hello') = {hashHex}");

    if (hashHex == expected)
        Console.WriteLine("OK SHA-256 correct!");
    else
    {
        Console.WriteLine("FAIL SHA-256 mismatch!");
        Console.WriteLine($"Expected: {expected}");
    }

    Console.WriteLine();
}

static void TestX25519(EncryptionModule em)
{
    Console.WriteLine("X25519 ECDH Test:");
    Console.WriteLine(new string('-', 30));

    var alice = em.X25519GenerateKeypair();
    var bob = em.X25519GenerateKeypair();

    Console.WriteLine($"Alice public key: {BytesToHex(alice.PublicKey)}");
    Console.WriteLine($"Bob public key: {BytesToHex(bob.PublicKey)}");

    var aliceSecret = em.X25519SharedSecret(alice.PrivateKey, bob.PublicKey);
    var bobSecret = em.X25519SharedSecret(bob.PrivateKey, alice.PublicKey);

    Console.WriteLine($"Alice's shared secret: {BytesToHex(aliceSecret)}");
    Console.WriteLine($"Bob's shared secret: {BytesToHex(bobSecret)}");

    if (aliceSecret.SequenceEqual(bobSecret))
        Console.WriteLine("OK X25519 key exchange successful!");
    else
        Console.WriteLine("FAIL Shared secrets don't match!");

    Console.WriteLine();
}

static void TestSecp256k1(EncryptionModule em)
{
    Console.WriteLine("secp256k1 ECDH + ECDSA Test:");
    Console.WriteLine(new string('-', 30));

    var kp = em.Secp256k1GenerateKeypair();
    Console.WriteLine($"Public key: {BytesToHex(kp.PublicKey)}");

    var message = "Hello, Bitcoin!"u8.ToArray();
    var signature = em.Secp256k1Sign(kp.PrivateKey, message);
    Console.WriteLine($"Signature: {BytesToHex(signature)}");

    if (em.Secp256k1Verify(kp.PublicKey, message, signature))
        Console.WriteLine("OK secp256k1 signature verified!");
    else
        Console.WriteLine("FAIL secp256k1 signature verification failed!");

    var wrongMessage = "Wrong message"u8.ToArray();
    if (!em.Secp256k1Verify(kp.PublicKey, wrongMessage, signature))
        Console.WriteLine("OK Wrong message correctly rejected!");
    else
        Console.WriteLine("FAIL Wrong message was accepted!");

    Console.WriteLine();
}

static void TestP256(EncryptionModule em)
{
    Console.WriteLine("P-256 ECDH + ECDSA Test:");
    Console.WriteLine(new string('-', 30));

    var kp = em.P256GenerateKeypair();
    Console.WriteLine($"Public key: {BytesToHex(kp.PublicKey)}");

    var message = "Hello, NIST!"u8.ToArray();
    var signature = em.P256Sign(kp.PrivateKey, message);
    Console.WriteLine($"Signature: {BytesToHex(signature)}");

    if (em.P256Verify(kp.PublicKey, message, signature))
        Console.WriteLine("OK P-256 signature verified!");
    else
        Console.WriteLine("FAIL P-256 signature verification failed!");

    Console.WriteLine();
}

static void TestEd25519(EncryptionModule em)
{
    Console.WriteLine("Ed25519 Signature Test:");
    Console.WriteLine(new string('-', 30));

    var kp = em.Ed25519GenerateKeypair();
    Console.WriteLine($"Public key: {BytesToHex(kp.PublicKey)}");

    var message = "Hello, Ed25519!"u8.ToArray();
    var signature = em.Ed25519Sign(kp.PrivateKey, message);
    Console.WriteLine($"Signature: {BytesToHex(signature)}");

    if (em.Ed25519Verify(kp.PublicKey, message, signature))
        Console.WriteLine("OK Ed25519 signature verified!");
    else
        Console.WriteLine("FAIL Ed25519 signature verification failed!");

    Console.WriteLine();
}

static string BytesToHex(byte[] bytes)
{
    return Convert.ToHexString(bytes).ToLowerInvariant();
}
