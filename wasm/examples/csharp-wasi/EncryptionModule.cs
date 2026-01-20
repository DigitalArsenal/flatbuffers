using System.Security.Cryptography;
using System.Text;
using Wasmtime;

namespace FlatBuffers.Encryption;

/// <summary>
/// FlatBuffers WASI Encryption Module for C#/.NET.
///
/// This class provides encryption functionality using Crypto++ compiled to WASM,
/// executed via the Wasmtime WebAssembly runtime.
///
/// Features:
/// - AES-256-CTR symmetric encryption
/// - X25519 ECDH key exchange
/// - secp256k1 ECDH and ECDSA signatures (Bitcoin/Ethereum compatible)
/// - P-256 ECDH and ECDSA signatures (NIST)
/// - Ed25519 signatures
/// - SHA-256 hashing
/// - HKDF key derivation
/// </summary>
public class EncryptionModule : IDisposable
{
    // Key and signature sizes
    public const int AesKeySize = 32;
    public const int AesIvSize = 16;
    public const int Sha256Size = 32;
    public const int SharedSecretSize = 32;

    public const int X25519PrivateKeySize = 32;
    public const int X25519PublicKeySize = 32;

    public const int Secp256k1PrivateKeySize = 32;
    public const int Secp256k1PublicKeySize = 33;  // compressed
    public const int Secp256k1SignatureSize = 72;  // DER encoded max

    public const int P256PrivateKeySize = 32;
    public const int P256PublicKeySize = 33;       // compressed
    public const int P256SignatureSize = 72;       // DER encoded max

    public const int Ed25519PrivateKeySize = 64;   // seed + public key
    public const int Ed25519PublicKeySize = 32;
    public const int Ed25519SignatureSize = 64;

    private const string DefaultWasmPath = "../../../build/wasm/wasm/flatc-encryption.wasm";

    private readonly Engine _engine;
    private readonly Store _store;
    private readonly Linker _linker;
    private readonly Instance _instance;
    private readonly Memory _memory;

    // Exported functions
    private readonly Function _malloc;
    private readonly Function _free;
    private readonly Function _getVersion;
    private readonly Function _hasCryptopp;
    private readonly Function _encryptBytes;
    private readonly Function _decryptBytes;
    private readonly Function _sha256;
    private readonly Function _hkdf;
    private readonly Function _x25519GenerateKeypair;
    private readonly Function _x25519SharedSecret;
    private readonly Function _secp256k1GenerateKeypair;
    private readonly Function _secp256k1SharedSecret;
    private readonly Function _secp256k1Sign;
    private readonly Function _secp256k1Verify;
    private readonly Function _p256GenerateKeypair;
    private readonly Function _p256SharedSecret;
    private readonly Function _p256Sign;
    private readonly Function _p256Verify;
    private readonly Function _ed25519GenerateKeypair;
    private readonly Function _ed25519Sign;
    private readonly Function _ed25519Verify;
    private readonly Function _deriveSymmetricKey;

    // Exception state
    private int _threwValue;
    private int _threwType;

    // Table for invoke_* trampolines
    private Table? _functionTable;

    /// <summary>
    /// Creates a new EncryptionModule using the default WASM path.
    /// </summary>
    public EncryptionModule() : this(DefaultWasmPath)
    {
    }

    /// <summary>
    /// Creates a new EncryptionModule from the specified WASM file path.
    /// </summary>
    public EncryptionModule(string wasmPath) : this(File.ReadAllBytes(wasmPath))
    {
    }

    /// <summary>
    /// Creates a new EncryptionModule from WASM bytes.
    /// </summary>
    public EncryptionModule(byte[] wasmBytes)
    {
        _engine = new Engine();
        _store = new Store(_engine);
        _linker = new Linker(_engine);

        // Define WASI imports
        DefineWasiImports();

        // Define Emscripten exception handling imports
        DefineEmscriptenImports();

        // Compile and instantiate the module
        var module = Module.FromBytes(_engine, "flatc-encryption", wasmBytes);
        _instance = _linker.Instantiate(_store, module);

        // Get memory
        _memory = _instance.GetMemory("memory")
            ?? throw new InvalidOperationException("Memory export not found");

        // Get function table for invoke_* trampolines
        _functionTable = _instance.GetTable("__indirect_function_table");

        // Get exported functions
        _malloc = GetFunction("malloc");
        _free = GetFunction("free");
        _getVersion = GetFunction("get_version");
        _hasCryptopp = GetFunction("has_cryptopp");
        _encryptBytes = GetFunction("encrypt_bytes");
        _decryptBytes = GetFunction("decrypt_bytes");
        _sha256 = GetFunction("sha256");
        _hkdf = GetFunction("hkdf");
        _x25519GenerateKeypair = GetFunction("x25519_generate_keypair");
        _x25519SharedSecret = GetFunction("x25519_shared_secret");
        _secp256k1GenerateKeypair = GetFunction("secp256k1_generate_keypair");
        _secp256k1SharedSecret = GetFunction("secp256k1_shared_secret");
        _secp256k1Sign = GetFunction("secp256k1_sign");
        _secp256k1Verify = GetFunction("secp256k1_verify");
        _p256GenerateKeypair = GetFunction("p256_generate_keypair");
        _p256SharedSecret = GetFunction("p256_shared_secret");
        _p256Sign = GetFunction("p256_sign");
        _p256Verify = GetFunction("p256_verify");
        _ed25519GenerateKeypair = GetFunction("ed25519_generate_keypair");
        _ed25519Sign = GetFunction("ed25519_sign");
        _ed25519Verify = GetFunction("ed25519_verify");
        _deriveSymmetricKey = GetFunction("derive_symmetric_key");
    }

    private Function GetFunction(string name)
    {
        return _instance.GetFunction(name)
            ?? throw new InvalidOperationException($"Function {name} not found");
    }

    private void DefineWasiImports()
    {
        // Minimal WASI implementations
        _linker.DefineFunction("wasi_snapshot_preview1", "fd_close",
            (Caller caller, int fd) => 0);

        _linker.DefineFunction("wasi_snapshot_preview1", "fd_seek",
            (Caller caller, int fd, long offset, int whence, int newOffsetPtr) => 0);

        _linker.DefineFunction("wasi_snapshot_preview1", "fd_write",
            (Caller caller, int fd, int iovs, int iovsLen, int nwrittenPtr) =>
            {
                // Basic stdout/stderr support
                if (fd == 1 || fd == 2)
                {
                    var memory = caller.GetMemory("memory");
                    if (memory != null)
                    {
                        int totalWritten = 0;
                        for (int i = 0; i < iovsLen; i++)
                        {
                            int baseOffset = iovs + i * 8;
                            int bufPtr = memory.ReadInt32(baseOffset);
                            int bufLen = memory.ReadInt32(baseOffset + 4);
                            totalWritten += bufLen;
                        }
                        memory.WriteInt32(nwrittenPtr, totalWritten);
                    }
                }
                return 0;
            });

        _linker.DefineFunction("wasi_snapshot_preview1", "fd_read",
            (Caller caller, int fd, int iovs, int iovsLen, int nreadPtr) =>
            {
                var memory = caller.GetMemory("memory");
                memory?.WriteInt32(nreadPtr, 0);
                return 0;
            });

        _linker.DefineFunction("wasi_snapshot_preview1", "environ_sizes_get",
            (Caller caller, int countPtr, int sizePtr) =>
            {
                var memory = caller.GetMemory("memory");
                if (memory != null)
                {
                    memory.WriteInt32(countPtr, 0);
                    memory.WriteInt32(sizePtr, 0);
                }
                return 0;
            });

        _linker.DefineFunction("wasi_snapshot_preview1", "environ_get",
            (Caller caller, int environ, int environBuf) => 0);

        _linker.DefineFunction("wasi_snapshot_preview1", "clock_time_get",
            (Caller caller, int clockId, long precision, int timePtr) =>
            {
                var memory = caller.GetMemory("memory");
                if (memory != null)
                {
                    long nanos = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() * 1_000_000;
                    memory.WriteInt64(timePtr, nanos);
                }
                return 0;
            });

        _linker.DefineFunction("wasi_snapshot_preview1", "proc_exit",
            (Caller caller, int code) => { });

        _linker.DefineFunction("wasi_snapshot_preview1", "random_get",
            (Caller caller, int buf, int bufLen) =>
            {
                var memory = caller.GetMemory("memory");
                if (memory != null)
                {
                    var randomBytes = RandomNumberGenerator.GetBytes(bufLen);
                    memory.Write(buf, randomBytes);
                }
                return 0;
            });
    }

    private void DefineEmscriptenImports()
    {
        // setThrew - called when an exception is thrown
        _linker.DefineFunction("env", "setThrew",
            (Caller caller, int value, int type) =>
            {
                _threwValue = value;
                _threwType = type;
            });

        // Exception handling stubs
        _linker.DefineFunction("env", "__cxa_find_matching_catch_2",
            (Caller caller) => 0);

        _linker.DefineFunction("env", "__cxa_find_matching_catch_3",
            (Caller caller, int arg) => 0);

        _linker.DefineFunction("env", "__resumeException",
            (Caller caller, int ptr) => { });

        _linker.DefineFunction("env", "__cxa_begin_catch",
            (Caller caller, int ptr) => 0);

        _linker.DefineFunction("env", "__cxa_end_catch",
            (Caller caller) => { });

        _linker.DefineFunction("env", "llvm_eh_typeid_for",
            (Caller caller, int ptr) => 0);

        _linker.DefineFunction("env", "__cxa_throw",
            (Caller caller, int ptr, int type, int destructor) => { });

        _linker.DefineFunction("env", "__cxa_uncaught_exceptions",
            (Caller caller) => 0);

        // invoke_* trampolines - call functions from the indirect function table
        DefineInvokeTrampolines();
    }

    private void DefineInvokeTrampolines()
    {
        // invoke_v: (idx) -> void
        _linker.DefineFunction("env", "invoke_v",
            (Caller caller, int idx) => InvokeTableFunction(caller, idx, Array.Empty<object>()));

        // invoke_vi: (idx, i32) -> void
        _linker.DefineFunction("env", "invoke_vi",
            (Caller caller, int idx, int a) => InvokeTableFunction(caller, idx, new object[] { a }));

        // invoke_vii: (idx, i32, i32) -> void
        _linker.DefineFunction("env", "invoke_vii",
            (Caller caller, int idx, int a, int b) => InvokeTableFunction(caller, idx, new object[] { a, b }));

        // invoke_viii: (idx, i32, i32, i32) -> void
        _linker.DefineFunction("env", "invoke_viii",
            (Caller caller, int idx, int a, int b, int c) => InvokeTableFunction(caller, idx, new object[] { a, b, c }));

        // invoke_viiii: (idx, i32 x 4) -> void
        _linker.DefineFunction("env", "invoke_viiii",
            (Caller caller, int idx, int a, int b, int c, int d) =>
                InvokeTableFunction(caller, idx, new object[] { a, b, c, d }));

        // invoke_viiiii: (idx, i32 x 5) -> void
        _linker.DefineFunction("env", "invoke_viiiii",
            (Caller caller, int idx, int a, int b, int c, int d, int e) =>
                InvokeTableFunction(caller, idx, new object[] { a, b, c, d, e }));

        // invoke_viiiiii: (idx, i32 x 6) -> void
        _linker.DefineFunction("env", "invoke_viiiiii",
            (Caller caller, int idx, int a, int b, int c, int d, int e, int f) =>
                InvokeTableFunction(caller, idx, new object[] { a, b, c, d, e, f }));

        // invoke_viiiiiii: (idx, i32 x 7) -> void
        _linker.DefineFunction("env", "invoke_viiiiiii",
            (Caller caller, int idx, int a, int b, int c, int d, int e, int f, int g) =>
                InvokeTableFunction(caller, idx, new object[] { a, b, c, d, e, f, g }));

        // invoke_viiiiiiiii: (idx, i32 x 9) -> void
        _linker.DefineFunction("env", "invoke_viiiiiiiii",
            (Caller caller, int idx, int a, int b, int c, int d, int e, int f, int g, int h, int ii) =>
                InvokeTableFunction(caller, idx, new object[] { a, b, c, d, e, f, g, h, ii }));

        // invoke_i: (idx) -> i32
        _linker.DefineFunction("env", "invoke_i",
            (Caller caller, int idx) => InvokeTableFunctionInt(caller, idx, Array.Empty<object>()));

        // invoke_ii: (idx, i32) -> i32
        _linker.DefineFunction("env", "invoke_ii",
            (Caller caller, int idx, int a) => InvokeTableFunctionInt(caller, idx, new object[] { a }));

        // invoke_iii: (idx, i32, i32) -> i32
        _linker.DefineFunction("env", "invoke_iii",
            (Caller caller, int idx, int a, int b) => InvokeTableFunctionInt(caller, idx, new object[] { a, b }));

        // invoke_iiii: (idx, i32 x 3) -> i32
        _linker.DefineFunction("env", "invoke_iiii",
            (Caller caller, int idx, int a, int b, int c) =>
                InvokeTableFunctionInt(caller, idx, new object[] { a, b, c }));

        // invoke_iiiii: (idx, i32 x 4) -> i32
        _linker.DefineFunction("env", "invoke_iiiii",
            (Caller caller, int idx, int a, int b, int c, int d) =>
                InvokeTableFunctionInt(caller, idx, new object[] { a, b, c, d }));

        // invoke_iiiiii: (idx, i32 x 5) -> i32
        _linker.DefineFunction("env", "invoke_iiiiii",
            (Caller caller, int idx, int a, int b, int c, int d, int e) =>
                InvokeTableFunctionInt(caller, idx, new object[] { a, b, c, d, e }));

        // invoke_iiiiiii: (idx, i32 x 6) -> i32
        _linker.DefineFunction("env", "invoke_iiiiiii",
            (Caller caller, int idx, int a, int b, int c, int d, int e, int f) =>
                InvokeTableFunctionInt(caller, idx, new object[] { a, b, c, d, e, f }));

        // invoke_iiiiiiii: (idx, i32 x 7) -> i32
        _linker.DefineFunction("env", "invoke_iiiiiiii",
            (Caller caller, int idx, int a, int b, int c, int d, int e, int f, int g) =>
                InvokeTableFunctionInt(caller, idx, new object[] { a, b, c, d, e, f, g }));

        // invoke_iiiiiiiiii: (idx, i32 x 9) -> i32
        _linker.DefineFunction("env", "invoke_iiiiiiiiii",
            (Caller caller, int idx, int a, int b, int c, int d, int e, int f, int g, int h, int ii) =>
                InvokeTableFunctionInt(caller, idx, new object[] { a, b, c, d, e, f, g, h, ii }));
    }

    private void InvokeTableFunction(Caller caller, int idx, object[] args)
    {
        try
        {
            if (_functionTable != null && idx < (int)_functionTable.GetSize())
            {
                var func = _functionTable.GetElement((uint)idx) as Function;
                func?.Invoke(args);
            }
        }
        catch
        {
            _threwValue = 1;
            _threwType = 0;
        }
    }

    private int InvokeTableFunctionInt(Caller caller, int idx, object[] args)
    {
        try
        {
            if (_functionTable != null && idx < (int)_functionTable.GetSize())
            {
                var func = _functionTable.GetElement((uint)idx) as Function;
                if (func != null)
                {
                    var result = func.Invoke(args);
                    if (result is int i) return i;
                }
            }
        }
        catch
        {
            _threwValue = 1;
            _threwType = 0;
        }
        return 0;
    }

    // Memory helpers
    private int Allocate(int size)
    {
        var result = _malloc.Invoke(size);
        return (int)result!;
    }

    private void Deallocate(int ptr)
    {
        _free.Invoke(ptr);
    }

    private void WriteBytes(int ptr, byte[] data)
    {
        _memory.Write(ptr, data);
    }

    private byte[] ReadBytes(int ptr, int length)
    {
        return _memory.Read(ptr, length).ToArray();
    }

    // Public API

    /// <summary>
    /// Returns the module version string.
    /// </summary>
    public string Version()
    {
        var ptr = (int)_getVersion.Invoke()!;
        if (ptr == 0) return "unknown";

        var bytes = new List<byte>();
        int i = 0;
        while (true)
        {
            var b = _memory.ReadByte(ptr + i);
            if (b == 0) break;
            bytes.Add(b);
            i++;
        }
        return Encoding.UTF8.GetString(bytes.ToArray());
    }

    /// <summary>
    /// Returns true if Crypto++ is available.
    /// </summary>
    public bool HasCryptopp()
    {
        return (int)_hasCryptopp.Invoke()! != 0;
    }

    /// <summary>
    /// Encrypts data using AES-256-CTR.
    /// </summary>
    public byte[] Encrypt(byte[] key, byte[] iv, byte[] plaintext)
    {
        if (key.Length != AesKeySize)
            throw new ArgumentException($"Key must be {AesKeySize} bytes", nameof(key));
        if (iv.Length != AesIvSize)
            throw new ArgumentException($"IV must be {AesIvSize} bytes", nameof(iv));
        if (plaintext.Length == 0)
            return Array.Empty<byte>();

        var keyPtr = Allocate(AesKeySize);
        var ivPtr = Allocate(AesIvSize);
        var dataPtr = Allocate(plaintext.Length);

        try
        {
            WriteBytes(keyPtr, key);
            WriteBytes(ivPtr, iv);
            WriteBytes(dataPtr, plaintext);

            _encryptBytes.Invoke(keyPtr, ivPtr, dataPtr, plaintext.Length);

            return ReadBytes(dataPtr, plaintext.Length);
        }
        finally
        {
            Deallocate(keyPtr);
            Deallocate(ivPtr);
            Deallocate(dataPtr);
        }
    }

    /// <summary>
    /// Decrypts data using AES-256-CTR.
    /// </summary>
    public byte[] Decrypt(byte[] key, byte[] iv, byte[] ciphertext)
    {
        if (key.Length != AesKeySize)
            throw new ArgumentException($"Key must be {AesKeySize} bytes", nameof(key));
        if (iv.Length != AesIvSize)
            throw new ArgumentException($"IV must be {AesIvSize} bytes", nameof(iv));
        if (ciphertext.Length == 0)
            return Array.Empty<byte>();

        var keyPtr = Allocate(AesKeySize);
        var ivPtr = Allocate(AesIvSize);
        var dataPtr = Allocate(ciphertext.Length);

        try
        {
            WriteBytes(keyPtr, key);
            WriteBytes(ivPtr, iv);
            WriteBytes(dataPtr, ciphertext);

            _decryptBytes.Invoke(keyPtr, ivPtr, dataPtr, ciphertext.Length);

            return ReadBytes(dataPtr, ciphertext.Length);
        }
        finally
        {
            Deallocate(keyPtr);
            Deallocate(ivPtr);
            Deallocate(dataPtr);
        }
    }

    /// <summary>
    /// Computes SHA-256 hash of data.
    /// </summary>
    public byte[] Sha256(byte[] data)
    {
        var dataPtr = Allocate(Math.Max(data.Length, 1));
        var hashPtr = Allocate(Sha256Size);

        try
        {
            if (data.Length > 0)
                WriteBytes(dataPtr, data);

            _sha256.Invoke(dataPtr, data.Length, hashPtr);

            return ReadBytes(hashPtr, Sha256Size);
        }
        finally
        {
            Deallocate(dataPtr);
            Deallocate(hashPtr);
        }
    }

    /// <summary>
    /// Derives a key using HKDF-SHA256.
    /// </summary>
    public byte[] Hkdf(byte[] ikm, byte[] salt, byte[] info, int length)
    {
        var ikmPtr = Allocate(Math.Max(ikm.Length, 1));
        var saltPtr = Allocate(Math.Max(salt.Length, 1));
        var infoPtr = Allocate(Math.Max(info.Length, 1));
        var outPtr = Allocate(length);

        try
        {
            if (ikm.Length > 0) WriteBytes(ikmPtr, ikm);
            if (salt.Length > 0) WriteBytes(saltPtr, salt);
            if (info.Length > 0) WriteBytes(infoPtr, info);

            _hkdf.Invoke(ikmPtr, ikm.Length, saltPtr, salt.Length, infoPtr, info.Length, outPtr, length);

            return ReadBytes(outPtr, length);
        }
        finally
        {
            Deallocate(ikmPtr);
            Deallocate(saltPtr);
            Deallocate(infoPtr);
            Deallocate(outPtr);
        }
    }

    /// <summary>
    /// Generates an X25519 key pair.
    /// </summary>
    public KeyPair X25519GenerateKeypair()
    {
        var privPtr = Allocate(X25519PrivateKeySize);
        var pubPtr = Allocate(X25519PublicKeySize);

        try
        {
            _x25519GenerateKeypair.Invoke(privPtr, pubPtr);

            return new KeyPair(
                ReadBytes(privPtr, X25519PrivateKeySize),
                ReadBytes(pubPtr, X25519PublicKeySize)
            );
        }
        finally
        {
            Deallocate(privPtr);
            Deallocate(pubPtr);
        }
    }

    /// <summary>
    /// Computes X25519 shared secret.
    /// </summary>
    public byte[] X25519SharedSecret(byte[] privateKey, byte[] publicKey)
    {
        var privPtr = Allocate(X25519PrivateKeySize);
        var pubPtr = Allocate(X25519PublicKeySize);
        var secretPtr = Allocate(SharedSecretSize);

        try
        {
            WriteBytes(privPtr, privateKey);
            WriteBytes(pubPtr, publicKey);

            _x25519SharedSecret.Invoke(privPtr, pubPtr, secretPtr);

            return ReadBytes(secretPtr, SharedSecretSize);
        }
        finally
        {
            Deallocate(privPtr);
            Deallocate(pubPtr);
            Deallocate(secretPtr);
        }
    }

    /// <summary>
    /// Generates a secp256k1 key pair.
    /// </summary>
    public KeyPair Secp256k1GenerateKeypair()
    {
        var privPtr = Allocate(Secp256k1PrivateKeySize);
        var pubPtr = Allocate(Secp256k1PublicKeySize);

        try
        {
            _secp256k1GenerateKeypair.Invoke(privPtr, pubPtr);

            return new KeyPair(
                ReadBytes(privPtr, Secp256k1PrivateKeySize),
                ReadBytes(pubPtr, Secp256k1PublicKeySize)
            );
        }
        finally
        {
            Deallocate(privPtr);
            Deallocate(pubPtr);
        }
    }

    /// <summary>
    /// Computes secp256k1 ECDH shared secret.
    /// </summary>
    public byte[] Secp256k1SharedSecret(byte[] privateKey, byte[] publicKey)
    {
        var privPtr = Allocate(Secp256k1PrivateKeySize);
        var pubPtr = Allocate(Secp256k1PublicKeySize);
        var secretPtr = Allocate(SharedSecretSize);

        try
        {
            WriteBytes(privPtr, privateKey);
            WriteBytes(pubPtr, publicKey);

            _secp256k1SharedSecret.Invoke(privPtr, pubPtr, secretPtr);

            return ReadBytes(secretPtr, SharedSecretSize);
        }
        finally
        {
            Deallocate(privPtr);
            Deallocate(pubPtr);
            Deallocate(secretPtr);
        }
    }

    /// <summary>
    /// Signs a message using secp256k1 ECDSA.
    /// </summary>
    public byte[] Secp256k1Sign(byte[] privateKey, byte[] message)
    {
        var privPtr = Allocate(Secp256k1PrivateKeySize);
        var msgPtr = Allocate(Math.Max(message.Length, 1));
        var sigPtr = Allocate(Secp256k1SignatureSize);
        var sigLenPtr = Allocate(4);

        try
        {
            WriteBytes(privPtr, privateKey);
            if (message.Length > 0) WriteBytes(msgPtr, message);

            _secp256k1Sign.Invoke(privPtr, msgPtr, message.Length, sigPtr, sigLenPtr);

            var sigLen = _memory.ReadInt32(sigLenPtr);
            return ReadBytes(sigPtr, sigLen);
        }
        finally
        {
            Deallocate(privPtr);
            Deallocate(msgPtr);
            Deallocate(sigPtr);
            Deallocate(sigLenPtr);
        }
    }

    /// <summary>
    /// Verifies a secp256k1 ECDSA signature.
    /// </summary>
    public bool Secp256k1Verify(byte[] publicKey, byte[] message, byte[] signature)
    {
        var pubPtr = Allocate(Secp256k1PublicKeySize);
        var msgPtr = Allocate(Math.Max(message.Length, 1));
        var sigPtr = Allocate(signature.Length);

        try
        {
            WriteBytes(pubPtr, publicKey);
            if (message.Length > 0) WriteBytes(msgPtr, message);
            WriteBytes(sigPtr, signature);

            var result = (int)_secp256k1Verify.Invoke(pubPtr, msgPtr, message.Length, sigPtr, signature.Length)!;
            return result != 0;
        }
        finally
        {
            Deallocate(pubPtr);
            Deallocate(msgPtr);
            Deallocate(sigPtr);
        }
    }

    /// <summary>
    /// Generates a P-256 key pair.
    /// </summary>
    public KeyPair P256GenerateKeypair()
    {
        var privPtr = Allocate(P256PrivateKeySize);
        var pubPtr = Allocate(P256PublicKeySize);

        try
        {
            _p256GenerateKeypair.Invoke(privPtr, pubPtr);

            return new KeyPair(
                ReadBytes(privPtr, P256PrivateKeySize),
                ReadBytes(pubPtr, P256PublicKeySize)
            );
        }
        finally
        {
            Deallocate(privPtr);
            Deallocate(pubPtr);
        }
    }

    /// <summary>
    /// Computes P-256 ECDH shared secret.
    /// </summary>
    public byte[] P256SharedSecret(byte[] privateKey, byte[] publicKey)
    {
        var privPtr = Allocate(P256PrivateKeySize);
        var pubPtr = Allocate(P256PublicKeySize);
        var secretPtr = Allocate(SharedSecretSize);

        try
        {
            WriteBytes(privPtr, privateKey);
            WriteBytes(pubPtr, publicKey);

            _p256SharedSecret.Invoke(privPtr, pubPtr, secretPtr);

            return ReadBytes(secretPtr, SharedSecretSize);
        }
        finally
        {
            Deallocate(privPtr);
            Deallocate(pubPtr);
            Deallocate(secretPtr);
        }
    }

    /// <summary>
    /// Signs a message using P-256 ECDSA.
    /// </summary>
    public byte[] P256Sign(byte[] privateKey, byte[] message)
    {
        var privPtr = Allocate(P256PrivateKeySize);
        var msgPtr = Allocate(Math.Max(message.Length, 1));
        var sigPtr = Allocate(P256SignatureSize);
        var sigLenPtr = Allocate(4);

        try
        {
            WriteBytes(privPtr, privateKey);
            if (message.Length > 0) WriteBytes(msgPtr, message);

            _p256Sign.Invoke(privPtr, msgPtr, message.Length, sigPtr, sigLenPtr);

            var sigLen = _memory.ReadInt32(sigLenPtr);
            return ReadBytes(sigPtr, sigLen);
        }
        finally
        {
            Deallocate(privPtr);
            Deallocate(msgPtr);
            Deallocate(sigPtr);
            Deallocate(sigLenPtr);
        }
    }

    /// <summary>
    /// Verifies a P-256 ECDSA signature.
    /// </summary>
    public bool P256Verify(byte[] publicKey, byte[] message, byte[] signature)
    {
        var pubPtr = Allocate(P256PublicKeySize);
        var msgPtr = Allocate(Math.Max(message.Length, 1));
        var sigPtr = Allocate(signature.Length);

        try
        {
            WriteBytes(pubPtr, publicKey);
            if (message.Length > 0) WriteBytes(msgPtr, message);
            WriteBytes(sigPtr, signature);

            var result = (int)_p256Verify.Invoke(pubPtr, msgPtr, message.Length, sigPtr, signature.Length)!;
            return result != 0;
        }
        finally
        {
            Deallocate(pubPtr);
            Deallocate(msgPtr);
            Deallocate(sigPtr);
        }
    }

    /// <summary>
    /// Generates an Ed25519 key pair.
    /// </summary>
    public KeyPair Ed25519GenerateKeypair()
    {
        var privPtr = Allocate(Ed25519PrivateKeySize);
        var pubPtr = Allocate(Ed25519PublicKeySize);

        try
        {
            _ed25519GenerateKeypair.Invoke(privPtr, pubPtr);

            return new KeyPair(
                ReadBytes(privPtr, Ed25519PrivateKeySize),
                ReadBytes(pubPtr, Ed25519PublicKeySize)
            );
        }
        finally
        {
            Deallocate(privPtr);
            Deallocate(pubPtr);
        }
    }

    /// <summary>
    /// Signs a message using Ed25519.
    /// </summary>
    public byte[] Ed25519Sign(byte[] privateKey, byte[] message)
    {
        var privPtr = Allocate(Ed25519PrivateKeySize);
        var msgPtr = Allocate(Math.Max(message.Length, 1));
        var sigPtr = Allocate(Ed25519SignatureSize);

        try
        {
            WriteBytes(privPtr, privateKey);
            if (message.Length > 0) WriteBytes(msgPtr, message);

            _ed25519Sign.Invoke(privPtr, msgPtr, message.Length, sigPtr);

            return ReadBytes(sigPtr, Ed25519SignatureSize);
        }
        finally
        {
            Deallocate(privPtr);
            Deallocate(msgPtr);
            Deallocate(sigPtr);
        }
    }

    /// <summary>
    /// Verifies an Ed25519 signature.
    /// </summary>
    public bool Ed25519Verify(byte[] publicKey, byte[] message, byte[] signature)
    {
        var pubPtr = Allocate(Ed25519PublicKeySize);
        var msgPtr = Allocate(Math.Max(message.Length, 1));
        var sigPtr = Allocate(Ed25519SignatureSize);

        try
        {
            WriteBytes(pubPtr, publicKey);
            if (message.Length > 0) WriteBytes(msgPtr, message);
            WriteBytes(sigPtr, signature);

            var result = (int)_ed25519Verify.Invoke(pubPtr, msgPtr, message.Length, sigPtr)!;
            return result != 0;
        }
        finally
        {
            Deallocate(pubPtr);
            Deallocate(msgPtr);
            Deallocate(sigPtr);
        }
    }

    /// <summary>
    /// Derives a symmetric key from a shared secret using HKDF.
    /// </summary>
    public DerivedKey DeriveSymmetricKey(byte[] sharedSecret, string context)
    {
        var contextBytes = Encoding.UTF8.GetBytes(context);

        var secretPtr = Allocate(sharedSecret.Length);
        var contextPtr = Allocate(Math.Max(contextBytes.Length, 1));
        var keyPtr = Allocate(AesKeySize);
        var ivPtr = Allocate(AesIvSize);

        try
        {
            WriteBytes(secretPtr, sharedSecret);
            if (contextBytes.Length > 0) WriteBytes(contextPtr, contextBytes);

            _deriveSymmetricKey.Invoke(secretPtr, sharedSecret.Length, contextPtr, contextBytes.Length, keyPtr, ivPtr);

            return new DerivedKey(
                ReadBytes(keyPtr, AesKeySize),
                ReadBytes(ivPtr, AesIvSize)
            );
        }
        finally
        {
            Deallocate(secretPtr);
            Deallocate(contextPtr);
            Deallocate(keyPtr);
            Deallocate(ivPtr);
        }
    }

    /// <summary>
    /// Generates random bytes using a secure random number generator.
    /// </summary>
    public static byte[] RandomBytes(int length)
    {
        return RandomNumberGenerator.GetBytes(length);
    }

    public void Dispose()
    {
        _store.Dispose();
        _engine.Dispose();
    }

    /// <summary>
    /// Represents a public/private key pair.
    /// </summary>
    public record KeyPair(byte[] PrivateKey, byte[] PublicKey);

    /// <summary>
    /// Represents a derived symmetric key and IV.
    /// </summary>
    public record DerivedKey(byte[] Key, byte[] Iv);
}
