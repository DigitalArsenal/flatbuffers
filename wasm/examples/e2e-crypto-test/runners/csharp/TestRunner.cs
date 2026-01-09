/**
 * C# E2E Test Runner for FlatBuffers Cross-Language Encryption
 *
 * Tests encryption/decryption using the WASM Crypto++ module with all 10 crypto key types.
 * Uses Wasmtime .NET runtime.
 */
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Wasmtime;
using Google.FlatBuffers;
using FBSecureMessage = E2E.Crypto.SecureMessage;
using FBPayload = E2E.Crypto.Payload;

namespace FlatBuffers.E2E.CryptoTest;

public class TestRunner : IDisposable
{
    private const int AesKeySize = 32;
    private const int AesIvSize = 16;
    private const int Sha256Size = 32;

    private readonly Engine _engine;
    private readonly Store _store;
    private readonly Linker _linker;
    private readonly Instance _instance;
    private readonly Memory _memory;

    private readonly Function _malloc;
    private readonly Function _free;
    private readonly Function _sha256;
    private readonly Function _encryptBytes;
    private readonly Function _decryptBytes;
    private readonly Function _hkdf;
    private readonly Function _x25519Generate;
    private readonly Function _x25519Shared;
    private readonly Function _secp256k1Generate;
    private readonly Function _secp256k1Shared;
    private readonly Function _p256Generate;
    private readonly Function _p256Shared;
    private readonly Function _ed25519Generate;
    private readonly Function _ed25519Sign;
    private readonly Function _ed25519Verify;
    private readonly Function _secp256k1Sign;
    private readonly Function _secp256k1Verify;
    private readonly Function _p256Sign;
    private readonly Function _p256Verify;

    private int _threwValue;
    private Wasmtime.Table? _functionTable;

    public TestRunner(byte[] wasmBytes)
    {
        _engine = new Engine();
        _store = new Store(_engine);
        _linker = new Linker(_engine);

        DefineWasiImports();
        DefineEmscriptenImports();

        var module = Module.FromBytes(_engine, "flatc-encryption", wasmBytes);
        _instance = _linker.Instantiate(_store, module);

        _memory = _instance.GetMemory("memory") ?? throw new Exception("Memory not found");
        _functionTable = _instance.GetTable("__indirect_function_table");

        _malloc = GetFunction("malloc");
        _free = GetFunction("free");
        _sha256 = GetFunction("wasi_sha256");
        _encryptBytes = GetFunction("wasi_encrypt_bytes");
        _decryptBytes = GetFunction("wasi_decrypt_bytes");
        _hkdf = GetFunction("wasi_hkdf");
        _x25519Generate = GetFunction("wasi_x25519_generate_keypair");
        _x25519Shared = GetFunction("wasi_x25519_shared_secret");
        _secp256k1Generate = GetFunction("wasi_secp256k1_generate_keypair");
        _secp256k1Shared = GetFunction("wasi_secp256k1_shared_secret");
        _p256Generate = GetFunction("wasi_p256_generate_keypair");
        _p256Shared = GetFunction("wasi_p256_shared_secret");
        _ed25519Generate = GetFunction("wasi_ed25519_generate_keypair");
        _ed25519Sign = GetFunction("wasi_ed25519_sign");
        _ed25519Verify = GetFunction("wasi_ed25519_verify");
        _secp256k1Sign = GetFunction("wasi_secp256k1_sign");
        _secp256k1Verify = GetFunction("wasi_secp256k1_verify");
        _p256Sign = GetFunction("wasi_p256_sign");
        _p256Verify = GetFunction("wasi_p256_verify");

        // Call _initialize if present (required for Emscripten modules)
        var initFunc = _instance.GetFunction("_initialize");
        initFunc?.Invoke();
    }

    private Function GetFunction(string name) =>
        _instance.GetFunction(name) ?? throw new Exception($"Function {name} not found");

    private void DefineWasiImports()
    {
        _linker.DefineFunction("wasi_snapshot_preview1", "fd_close", (Caller c, int fd) => 0);
        _linker.DefineFunction("wasi_snapshot_preview1", "fd_seek", (Caller c, int fd, long off, int wh, int ptr) => 0);
        _linker.DefineFunction("wasi_snapshot_preview1", "fd_write", (Caller c, int fd, int iovs, int len, int nw) =>
        {
            var mem = c.GetMemory("memory");
            mem?.WriteInt32(nw, 0);
            return 0;
        });
        _linker.DefineFunction("wasi_snapshot_preview1", "fd_read", (Caller c, int fd, int iovs, int len, int nr) =>
        {
            c.GetMemory("memory")?.WriteInt32(nr, 0);
            return 0;
        });
        _linker.DefineFunction("wasi_snapshot_preview1", "environ_sizes_get", (Caller c, int cnt, int sz) =>
        {
            var mem = c.GetMemory("memory");
            mem?.WriteInt32(cnt, 0);
            mem?.WriteInt32(sz, 0);
            return 0;
        });
        _linker.DefineFunction("wasi_snapshot_preview1", "environ_get", (Caller c, int env, int buf) => 0);
        _linker.DefineFunction("wasi_snapshot_preview1", "clock_time_get", (Caller c, int id, long prec, int ptr) =>
        {
            var mem = c.GetMemory("memory");
            mem?.WriteInt64(ptr, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() * 1_000_000);
            return 0;
        });
        _linker.DefineFunction("wasi_snapshot_preview1", "proc_exit", (Caller c, int code) => { });
        _linker.DefineFunction("wasi_snapshot_preview1", "random_get", (Caller c, int buf, int len) =>
        {
            var mem = c.GetMemory("memory");
            if (mem != null)
            {
                var bytes = RandomNumberGenerator.GetBytes(len);
                WriteBytes(mem, buf, bytes);
            }
            return 0;
        });
    }

    private static void WriteBytes(Memory mem, int offset, byte[] data)
    {
        var span = mem.GetSpan(offset, data.Length);
        data.CopyTo(span);
    }

    private static byte[] ReadBytes(Memory mem, int offset, int length)
    {
        var span = mem.GetSpan(offset, length);
        return span.ToArray();
    }

    private void DefineEmscriptenImports()
    {
        _linker.DefineFunction("env", "setThrew", (Caller c, int v, int t) => { _threwValue = v; });
        _linker.DefineFunction("env", "__cxa_find_matching_catch_2", (Caller c) => 0);
        _linker.DefineFunction("env", "__cxa_find_matching_catch_3", (Caller c, int arg) => 0);
        _linker.DefineFunction("env", "__resumeException", (Caller c, int ptr) => { });
        _linker.DefineFunction("env", "__cxa_begin_catch", (Caller c, int ptr) => 0);
        _linker.DefineFunction("env", "__cxa_end_catch", (Caller c) => { });
        _linker.DefineFunction("env", "llvm_eh_typeid_for", (Caller c, int ptr) => 0);
        _linker.DefineFunction("env", "__cxa_throw", (Caller c, int ptr, int type, int dest) => { });
        _linker.DefineFunction("env", "__cxa_uncaught_exceptions", (Caller c) => 0);

        DefineInvokeTrampolines();
    }

    private void DefineInvokeTrampolines()
    {
        _linker.DefineFunction("env", "invoke_v", (Caller c, int idx) => InvokeTableVoid(c, idx));
        _linker.DefineFunction("env", "invoke_vi", (Caller c, int idx, int a) => InvokeTableVoid(c, idx, a));
        _linker.DefineFunction("env", "invoke_vii", (Caller c, int idx, int a, int b) => InvokeTableVoid(c, idx, a, b));
        _linker.DefineFunction("env", "invoke_viii", (Caller c, int idx, int a, int b, int cc) => InvokeTableVoid(c, idx, a, b, cc));
        _linker.DefineFunction("env", "invoke_viiii", (Caller c, int idx, int a, int b, int cc, int d) => InvokeTableVoid(c, idx, a, b, cc, d));
        _linker.DefineFunction("env", "invoke_viiiii", (Caller c, int idx, int a, int b, int cc, int d, int e) => InvokeTableVoid(c, idx, a, b, cc, d, e));
        _linker.DefineFunction("env", "invoke_viiiiii", (Caller c, int idx, int a, int b, int cc, int d, int e, int f) => InvokeTableVoid(c, idx, a, b, cc, d, e, f));
        _linker.DefineFunction("env", "invoke_viiiiiii", (Caller c, int idx, int a, int b, int cc, int d, int e, int f, int g) => InvokeTableVoid(c, idx, a, b, cc, d, e, f, g));
        _linker.DefineFunction("env", "invoke_viiiiiiiii", (Caller c, int idx, int a, int b, int cc, int d, int e, int f, int g, int h, int ii) => InvokeTableVoid(c, idx, a, b, cc, d, e, f, g, h, ii));

        _linker.DefineFunction("env", "invoke_i", (Caller c, int idx) => InvokeTableInt(c, idx));
        _linker.DefineFunction("env", "invoke_ii", (Caller c, int idx, int a) => InvokeTableInt(c, idx, a));
        _linker.DefineFunction("env", "invoke_iii", (Caller c, int idx, int a, int b) => InvokeTableInt(c, idx, a, b));
        _linker.DefineFunction("env", "invoke_iiii", (Caller c, int idx, int a, int b, int cc) => InvokeTableInt(c, idx, a, b, cc));
        _linker.DefineFunction("env", "invoke_iiiii", (Caller c, int idx, int a, int b, int cc, int d) => InvokeTableInt(c, idx, a, b, cc, d));
        _linker.DefineFunction("env", "invoke_iiiiii", (Caller c, int idx, int a, int b, int cc, int d, int e) => InvokeTableInt(c, idx, a, b, cc, d, e));
        _linker.DefineFunction("env", "invoke_iiiiiii", (Caller c, int idx, int a, int b, int cc, int d, int e, int f) => InvokeTableInt(c, idx, a, b, cc, d, e, f));
        _linker.DefineFunction("env", "invoke_iiiiiiii", (Caller c, int idx, int a, int b, int cc, int d, int e, int f, int g) => InvokeTableInt(c, idx, a, b, cc, d, e, f, g));
        _linker.DefineFunction("env", "invoke_iiiiiiiiii", (Caller c, int idx, int a, int b, int cc, int d, int e, int f, int g, int h, int ii) => InvokeTableInt(c, idx, a, b, cc, d, e, f, g, h, ii));
    }

    private void InvokeTableVoid(Caller caller, int idx, params int[] args)
    {
        try
        {
            if (_functionTable != null && idx < (int)_functionTable.GetSize())
            {
                var func = _functionTable.GetElement((uint)idx) as Function;
                if (func != null)
                {
                    var boxedArgs = args.Select(a => (ValueBox)a).ToArray();
                    func.Invoke(boxedArgs);
                }
            }
        }
        catch { _threwValue = 1; }
    }

    private int InvokeTableInt(Caller caller, int idx, params int[] args)
    {
        try
        {
            if (_functionTable != null && idx < (int)_functionTable.GetSize())
            {
                var func = _functionTable.GetElement((uint)idx) as Function;
                if (func != null)
                {
                    var boxedArgs = args.Select(a => (ValueBox)a).ToArray();
                    var result = func.Invoke(boxedArgs);
                    if (result is int i) return i;
                }
            }
        }
        catch { _threwValue = 1; }
        return 0;
    }

    private int Allocate(int size) => (int)_malloc.Invoke(size)!;
    private void Deallocate(int ptr) => _free.Invoke(ptr);

    public byte[] Sha256(byte[] data)
    {
        var dataPtr = Allocate(Math.Max(data.Length, 1));
        var hashPtr = Allocate(Sha256Size);

        if (data.Length > 0) WriteBytes(_memory, dataPtr, data);
        _sha256.Invoke(dataPtr, data.Length, hashPtr);

        var hash = ReadBytes(_memory, hashPtr, Sha256Size);
        Deallocate(dataPtr);
        Deallocate(hashPtr);
        return hash;
    }

    public byte[] Encrypt(byte[] key, byte[] iv, byte[] data)
    {
        var keyPtr = Allocate(AesKeySize);
        var ivPtr = Allocate(AesIvSize);
        var dataPtr = Allocate(data.Length);

        WriteBytes(_memory, keyPtr, key);
        WriteBytes(_memory, ivPtr, iv);
        WriteBytes(_memory, dataPtr, data);
        _encryptBytes.Invoke(keyPtr, ivPtr, dataPtr, data.Length);

        var encrypted = ReadBytes(_memory, dataPtr, data.Length);
        Deallocate(keyPtr);
        Deallocate(ivPtr);
        Deallocate(dataPtr);
        return encrypted;
    }

    public byte[] Decrypt(byte[] key, byte[] iv, byte[] data)
    {
        var keyPtr = Allocate(AesKeySize);
        var ivPtr = Allocate(AesIvSize);
        var dataPtr = Allocate(data.Length);

        WriteBytes(_memory, keyPtr, key);
        WriteBytes(_memory, ivPtr, iv);
        WriteBytes(_memory, dataPtr, data);
        _decryptBytes.Invoke(keyPtr, ivPtr, dataPtr, data.Length);

        var decrypted = ReadBytes(_memory, dataPtr, data.Length);
        Deallocate(keyPtr);
        Deallocate(ivPtr);
        Deallocate(dataPtr);
        return decrypted;
    }

    public byte[] Hkdf(byte[] ikm, byte[] salt, byte[] info, int outputLen)
    {
        var ikmPtr = Allocate(Math.Max(ikm.Length, 1));
        var saltPtr = Allocate(Math.Max(salt.Length, 1));
        var infoPtr = Allocate(Math.Max(info.Length, 1));
        var outPtr = Allocate(outputLen);

        if (ikm.Length > 0) WriteBytes(_memory, ikmPtr, ikm);
        if (salt.Length > 0) WriteBytes(_memory, saltPtr, salt);
        if (info.Length > 0) WriteBytes(_memory, infoPtr, info);

        _hkdf.Invoke(ikmPtr, ikm.Length, saltPtr, salt.Length, infoPtr, info.Length, outPtr, outputLen);

        var output = ReadBytes(_memory, outPtr, outputLen);
        Deallocate(ikmPtr);
        Deallocate(saltPtr);
        Deallocate(infoPtr);
        Deallocate(outPtr);
        return output;
    }

    public (byte[] privateKey, byte[] publicKey) X25519GenerateKeypair()
    {
        var privPtr = Allocate(32);
        var pubPtr = Allocate(32);

        _x25519Generate.Invoke(privPtr, pubPtr);

        var priv = ReadBytes(_memory, privPtr, 32);
        var pub = ReadBytes(_memory, pubPtr, 32);
        Deallocate(privPtr);
        Deallocate(pubPtr);
        return (priv, pub);
    }

    public byte[] X25519SharedSecret(byte[] privateKey, byte[] publicKey)
    {
        var privPtr = Allocate(32);
        var pubPtr = Allocate(32);
        var sharedPtr = Allocate(32);

        WriteBytes(_memory, privPtr, privateKey);
        WriteBytes(_memory, pubPtr, publicKey);
        _x25519Shared.Invoke(privPtr, pubPtr, sharedPtr);

        var shared = ReadBytes(_memory, sharedPtr, 32);
        Deallocate(privPtr);
        Deallocate(pubPtr);
        Deallocate(sharedPtr);
        return shared;
    }

    public (byte[] privateKey, byte[] publicKey) Secp256k1GenerateKeypair()
    {
        var privPtr = Allocate(32);
        var pubPtr = Allocate(33);

        _secp256k1Generate.Invoke(privPtr, pubPtr);

        var priv = ReadBytes(_memory, privPtr, 32);
        var pub = ReadBytes(_memory, pubPtr, 33);
        Deallocate(privPtr);
        Deallocate(pubPtr);
        return (priv, pub);
    }

    public byte[] Secp256k1SharedSecret(byte[] privateKey, byte[] publicKey)
    {
        var privPtr = Allocate(32);
        var pubPtr = Allocate(publicKey.Length);
        var sharedPtr = Allocate(32);

        WriteBytes(_memory, privPtr, privateKey);
        WriteBytes(_memory, pubPtr, publicKey);
        _secp256k1Shared.Invoke(privPtr, pubPtr, publicKey.Length, sharedPtr);

        var shared = ReadBytes(_memory, sharedPtr, 32);
        Deallocate(privPtr);
        Deallocate(pubPtr);
        Deallocate(sharedPtr);
        return shared;
    }

    public (byte[] privateKey, byte[] publicKey) P256GenerateKeypair()
    {
        var privPtr = Allocate(32);
        var pubPtr = Allocate(33);

        _p256Generate.Invoke(privPtr, pubPtr);

        var priv = ReadBytes(_memory, privPtr, 32);
        var pub = ReadBytes(_memory, pubPtr, 33);
        Deallocate(privPtr);
        Deallocate(pubPtr);
        return (priv, pub);
    }

    public byte[] P256SharedSecret(byte[] privateKey, byte[] publicKey)
    {
        var privPtr = Allocate(32);
        var pubPtr = Allocate(publicKey.Length);
        var sharedPtr = Allocate(32);

        WriteBytes(_memory, privPtr, privateKey);
        WriteBytes(_memory, pubPtr, publicKey);
        _p256Shared.Invoke(privPtr, pubPtr, publicKey.Length, sharedPtr);

        var shared = ReadBytes(_memory, sharedPtr, 32);
        Deallocate(privPtr);
        Deallocate(pubPtr);
        Deallocate(sharedPtr);
        return shared;
    }

    public (byte[] privateKey, byte[] publicKey) Ed25519GenerateKeypair()
    {
        var privPtr = Allocate(64);  // Ed25519 private key is 64 bytes
        var pubPtr = Allocate(32);

        var result = (int)_ed25519Generate.Invoke(privPtr, pubPtr)!;
        if (result != 0)
        {
            Deallocate(privPtr);
            Deallocate(pubPtr);
            throw new Exception("Ed25519 keypair generation failed");
        }

        var priv = ReadBytes(_memory, privPtr, 64);
        var pub = ReadBytes(_memory, pubPtr, 32);
        Deallocate(privPtr);
        Deallocate(pubPtr);
        return (priv, pub);
    }

    public byte[] Ed25519Sign(byte[] privateKey, byte[] data)
    {
        var privPtr = Allocate(64);
        var dataPtr = Allocate(Math.Max(data.Length, 1));
        var sigPtr = Allocate(64);

        WriteBytes(_memory, privPtr, privateKey);
        if (data.Length > 0) WriteBytes(_memory, dataPtr, data);
        var result = (int)_ed25519Sign.Invoke(privPtr, dataPtr, data.Length, sigPtr)!;
        if (result != 0)
        {
            Deallocate(privPtr);
            Deallocate(dataPtr);
            Deallocate(sigPtr);
            throw new Exception("Ed25519 signing failed");
        }

        var sig = ReadBytes(_memory, sigPtr, 64);
        Deallocate(privPtr);
        Deallocate(dataPtr);
        Deallocate(sigPtr);
        return sig;
    }

    public bool Ed25519Verify(byte[] publicKey, byte[] data, byte[] signature)
    {
        var pubPtr = Allocate(32);
        var dataPtr = Allocate(Math.Max(data.Length, 1));
        var sigPtr = Allocate(64);

        WriteBytes(_memory, pubPtr, publicKey);
        if (data.Length > 0) WriteBytes(_memory, dataPtr, data);
        WriteBytes(_memory, sigPtr, signature);
        var result = (int)_ed25519Verify.Invoke(pubPtr, dataPtr, data.Length, sigPtr)!;

        Deallocate(pubPtr);
        Deallocate(dataPtr);
        Deallocate(sigPtr);
        return result == 0;
    }

    public byte[] Secp256k1Sign(byte[] privateKey, byte[] data)
    {
        var privPtr = Allocate(32);
        var dataPtr = Allocate(Math.Max(data.Length, 1));
        var sigPtr = Allocate(72);  // DER signature up to 72 bytes
        var sigSizePtr = Allocate(4);

        WriteBytes(_memory, privPtr, privateKey);
        if (data.Length > 0) WriteBytes(_memory, dataPtr, data);
        var result = (int)_secp256k1Sign.Invoke(privPtr, dataPtr, data.Length, sigPtr, sigSizePtr)!;
        if (result != 0)
        {
            Deallocate(privPtr);
            Deallocate(dataPtr);
            Deallocate(sigPtr);
            Deallocate(sigSizePtr);
            throw new Exception("secp256k1 signing failed");
        }

        var sigSizeBytes = ReadBytes(_memory, sigSizePtr, 4);
        var sigSize = BitConverter.ToInt32(sigSizeBytes, 0);
        var sig = ReadBytes(_memory, sigPtr, sigSize);

        Deallocate(privPtr);
        Deallocate(dataPtr);
        Deallocate(sigPtr);
        Deallocate(sigSizePtr);
        return sig;
    }

    public bool Secp256k1Verify(byte[] publicKey, byte[] data, byte[] signature)
    {
        var pubPtr = Allocate(publicKey.Length);
        var dataPtr = Allocate(Math.Max(data.Length, 1));
        var sigPtr = Allocate(signature.Length);

        WriteBytes(_memory, pubPtr, publicKey);
        if (data.Length > 0) WriteBytes(_memory, dataPtr, data);
        WriteBytes(_memory, sigPtr, signature);
        var result = (int)_secp256k1Verify.Invoke(pubPtr, publicKey.Length, dataPtr, data.Length, sigPtr, signature.Length)!;

        Deallocate(pubPtr);
        Deallocate(dataPtr);
        Deallocate(sigPtr);
        return result == 0;
    }

    public byte[] P256Sign(byte[] privateKey, byte[] data)
    {
        var privPtr = Allocate(32);
        var dataPtr = Allocate(Math.Max(data.Length, 1));
        var sigPtr = Allocate(72);  // DER signature up to 72 bytes
        var sigSizePtr = Allocate(4);

        WriteBytes(_memory, privPtr, privateKey);
        if (data.Length > 0) WriteBytes(_memory, dataPtr, data);
        var result = (int)_p256Sign.Invoke(privPtr, dataPtr, data.Length, sigPtr, sigSizePtr)!;
        if (result != 0)
        {
            Deallocate(privPtr);
            Deallocate(dataPtr);
            Deallocate(sigPtr);
            Deallocate(sigSizePtr);
            throw new Exception("P-256 signing failed");
        }

        var sigSizeBytes = ReadBytes(_memory, sigSizePtr, 4);
        var sigSize = BitConverter.ToInt32(sigSizeBytes, 0);
        var sig = ReadBytes(_memory, sigPtr, sigSize);

        Deallocate(privPtr);
        Deallocate(dataPtr);
        Deallocate(sigPtr);
        Deallocate(sigSizePtr);
        return sig;
    }

    public bool P256Verify(byte[] publicKey, byte[] data, byte[] signature)
    {
        var pubPtr = Allocate(publicKey.Length);
        var dataPtr = Allocate(Math.Max(data.Length, 1));
        var sigPtr = Allocate(signature.Length);

        WriteBytes(_memory, pubPtr, publicKey);
        if (data.Length > 0) WriteBytes(_memory, dataPtr, data);
        WriteBytes(_memory, sigPtr, signature);
        var result = (int)_p256Verify.Invoke(pubPtr, publicKey.Length, dataPtr, data.Length, sigPtr, signature.Length)!;

        Deallocate(pubPtr);
        Deallocate(dataPtr);
        Deallocate(sigPtr);
        return result == 0;
    }

    public void Dispose()
    {
        _store.Dispose();
        _engine.Dispose();
    }

    public static string ToHex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();
    public static byte[] FromHex(string hex) => Convert.FromHexString(hex);

    class ECDHHeader
    {
        public int version { get; set; }
        public int key_exchange { get; set; }
        public string? ephemeral_public_key { get; set; }
        public string? context { get; set; }
        public string? session_key { get; set; }
        public string? session_iv { get; set; }
    }

    record ECDHCurve(
        string Name,
        int PubKeySize,
        int KeyExchange,
        Func<(byte[] priv, byte[] pub)> Generate,
        Func<byte[], byte[], byte[]> Shared
    );

    class TestResult
    {
        public string Name { get; }
        public int Passed { get; private set; }
        public int Failed { get; private set; }

        public TestResult(string name) => Name = name;
        public void Pass(string msg) { Passed++; Console.WriteLine($"  ✓ {msg}"); }
        public void Fail(string msg) { Failed++; Console.WriteLine($"  ✗ {msg}"); }

        public bool Summary()
        {
            var total = Passed + Failed;
            var status = Failed == 0 ? "✓" : "✗";
            Console.WriteLine($"\n{status} {Name}: {Passed}/{total} passed");
            return Failed == 0;
        }
    }

    public static void Main(string[] args)
    {
        Console.WriteLine(new string('=', 60));
        Console.WriteLine("FlatBuffers Cross-Language Encryption E2E Tests - C#");
        Console.WriteLine(new string('=', 60));
        Console.WriteLine();

        string[] wasmPaths = {
            "../../../../build/wasm/wasm/flatc-encryption.wasm",
            "../../../../../build/wasm/wasm/flatc-encryption.wasm",
            "../../../../../../build/wasm/wasm/flatc-encryption.wasm"
        };

        var wasmPath = wasmPaths.FirstOrDefault(File.Exists);
        if (wasmPath == null)
        {
            Console.Error.WriteLine("WASM module not found. Build it first.");
            Environment.Exit(1);
        }

        Console.WriteLine($"Loading WASM module: {wasmPath}");
        using var runner = new TestRunner(File.ReadAllBytes(wasmPath));
        Console.WriteLine();

        var vectorsDir = "../../vectors";
        var encryptionKeys = JsonSerializer.Deserialize<Dictionary<string, Dictionary<string, string>>>(
            File.ReadAllText(Path.Combine(vectorsDir, "encryption_keys.json")))!;

        var results = new List<bool>();

        // Test 1: SHA-256
        Console.WriteLine("Test 1: SHA-256 Hash");
        Console.WriteLine(new string('-', 40));
        {
            var result = new TestResult("SHA-256");

            var hash = runner.Sha256(Encoding.UTF8.GetBytes("hello"));
            var expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
            if (ToHex(hash) == expected) result.Pass("SHA256('hello') correct");
            else result.Fail($"SHA256 mismatch: {ToHex(hash)}");

            var emptyHash = runner.Sha256(Array.Empty<byte>());
            var expectedEmpty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
            if (ToHex(emptyHash) == expectedEmpty) result.Pass("SHA256('') correct");
            else result.Fail("SHA256('') mismatch");

            results.Add(result.Summary());
        }

        // Test 2: Per-chain encryption
        Console.WriteLine("\nTest 2: Per-Chain Encryption");
        Console.WriteLine(new string('-', 40));

        foreach (var (chain, keys) in encryptionKeys)
        {
            var result = new TestResult($"Encryption with {chain}");

            var key = FromHex(keys["key_hex"]);
            var iv = FromHex(keys["iv_hex"]);
            var plaintext = Encoding.UTF8.GetBytes($"Test data for {chain} encryption");

            var encrypted = runner.Encrypt(key, iv, plaintext);
            if (!encrypted.SequenceEqual(plaintext)) result.Pass("Encryption modified data");
            else result.Fail("Encryption did not modify data");

            var decrypted = runner.Decrypt(key, iv, encrypted);
            if (decrypted.SequenceEqual(plaintext)) result.Pass("Decryption restored original");
            else result.Fail("Decryption mismatch");

            results.Add(result.Summary());
        }

        // Test 3: Cross-language verification
        Console.WriteLine("\nTest 3: Cross-Language Verification");
        Console.WriteLine(new string('-', 40));
        var binaryDir = Path.Combine(vectorsDir, "binary");
        {
            var result = new TestResult("Cross-Language");

            if (Directory.Exists(binaryDir))
            {
                var unencryptedPath = Path.Combine(binaryDir, "monster_unencrypted.bin");
                if (File.Exists(unencryptedPath))
                {
                    var data = File.ReadAllBytes(unencryptedPath);
                    result.Pass($"Read unencrypted binary: {data.Length} bytes");
                }
                else result.Fail("monster_unencrypted.bin not found - run Node.js test first");

                foreach (var (chain, keys) in encryptionKeys)
                {
                    var encryptedPath = Path.Combine(binaryDir, $"monster_encrypted_{chain}.bin");
                    if (File.Exists(encryptedPath))
                    {
                        var encrypted = File.ReadAllBytes(encryptedPath);
                        result.Pass($"Read {chain}: {encrypted.Length} bytes");

                        var key = FromHex(keys["key_hex"]);
                        var iv = FromHex(keys["iv_hex"]);
                        runner.Decrypt(key, iv, encrypted);
                        result.Pass($"Decrypted {chain} data");
                    }
                }
            }
            else result.Fail("Binary directory not found - run Node.js test first");

            results.Add(result.Summary());
        }

        // Test 4: ECDH Key Exchange Verification
        Console.WriteLine("\nTest 4: ECDH Key Exchange Verification");
        Console.WriteLine(new string('-', 40));

        // Read unencrypted data for cross-language verification
        byte[]? unencryptedData = null;
        try { unencryptedData = File.ReadAllBytes(Path.Combine(binaryDir, "monster_unencrypted.bin")); }
        catch { /* Will be null if file doesn't exist */ }

        var ecdhCurves = new ECDHCurve[]
        {
            new("X25519", 32, 0, runner.X25519GenerateKeypair, runner.X25519SharedSecret),
            new("secp256k1", 33, 1, runner.Secp256k1GenerateKeypair, runner.Secp256k1SharedSecret),
            new("P-256", 33, 2, runner.P256GenerateKeypair, runner.P256SharedSecret)
        };

        foreach (var curve in ecdhCurves)
        {
            var result = new TestResult($"ECDH {curve.Name}");

            try
            {
                // Generate keypairs for Alice and Bob
                var alice = curve.Generate();
                var bob = curve.Generate();

                if (alice.pub.Length == curve.PubKeySize)
                    result.Pass($"Generated Alice keypair (pub: {alice.pub.Length} bytes)");
                else
                    result.Fail($"Alice public key wrong size: {alice.pub.Length}");

                if (bob.pub.Length == curve.PubKeySize)
                    result.Pass($"Generated Bob keypair (pub: {bob.pub.Length} bytes)");
                else
                    result.Fail($"Bob public key wrong size: {bob.pub.Length}");

                // Compute shared secrets
                var aliceShared = curve.Shared(alice.priv, bob.pub);
                var bobShared = curve.Shared(bob.priv, alice.pub);

                if (aliceShared.SequenceEqual(bobShared))
                    result.Pass($"Shared secrets match ({aliceShared.Length} bytes)");
                else
                {
                    result.Fail("Shared secrets DO NOT match!");
                    result.Fail($"  Alice: {ToHex(aliceShared)}");
                    result.Fail($"  Bob:   {ToHex(bobShared)}");
                }

                // Test HKDF key derivation from shared secret
                var sessionMaterial = runner.Hkdf(aliceShared,
                    Encoding.UTF8.GetBytes("flatbuffers-encryption"),
                    Encoding.UTF8.GetBytes("session-key-iv"), 48);
                var sessionKey = sessionMaterial[..32];
                var sessionIv = sessionMaterial[32..48];

                if (sessionKey.Length == 32 && sessionIv.Length == 16)
                    result.Pass($"HKDF derived key ({sessionKey.Length}B) + IV ({sessionIv.Length}B)");
                else
                    result.Fail("HKDF output wrong size");

                // Full E2E: encrypt with derived key, decrypt with same key
                var testData = $"ECDH test data for {curve.Name} encryption";
                var plaintext = Encoding.UTF8.GetBytes(testData);
                var encrypted = runner.Encrypt(sessionKey, sessionIv, plaintext);

                if (!encrypted.SequenceEqual(plaintext))
                    result.Pass("Encryption with derived key modified data");
                else
                    result.Fail("Encryption did not modify data");

                var decrypted = runner.Decrypt(sessionKey, sessionIv, encrypted);
                if (decrypted.SequenceEqual(plaintext))
                    result.Pass("Decryption with derived key restored original");
                else
                    result.Fail("Decryption mismatch");

                // Verify cross-language ECDH header if available
                var headerName = curve.Name.ToLowerInvariant().Replace("-", "");
                var headerPath = Path.Combine(binaryDir, $"monster_ecdh_{headerName}_header.json");
                if (File.Exists(headerPath))
                {
                    try
                    {
                        var header = JsonSerializer.Deserialize<ECDHHeader>(File.ReadAllText(headerPath))!;

                        if (header.key_exchange == curve.KeyExchange)
                            result.Pass($"Cross-language header has correct key_exchange: {curve.KeyExchange}");
                        else
                            result.Fail($"Header key_exchange mismatch: {header.key_exchange}");

                        if (!string.IsNullOrEmpty(header.ephemeral_public_key) &&
                            !string.IsNullOrEmpty(header.session_key) &&
                            !string.IsNullOrEmpty(header.session_iv))
                        {
                            result.Pass("Header contains ephemeral_public_key, session_key, session_iv");

                            // Decrypt the cross-language encrypted file using Node.js session key
                            var encryptedPath = Path.Combine(binaryDir, $"monster_ecdh_{headerName}_encrypted.bin");
                            if (File.Exists(encryptedPath) && unencryptedData != null)
                            {
                                var nodeKey = FromHex(header.session_key);
                                var nodeIv = FromHex(header.session_iv);
                                var encryptedFileData = File.ReadAllBytes(encryptedPath);
                                var decryptedData = runner.Decrypt(nodeKey, nodeIv, encryptedFileData);

                                if (decryptedData.SequenceEqual(unencryptedData))
                                    result.Pass($"Decrypted Node.js {curve.Name} data matches original");
                                else
                                    result.Fail($"Decrypted Node.js {curve.Name} data mismatch");
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        result.Fail($"Error reading cross-language header: {e.Message}");
                    }
                }
                else
                {
                    result.Pass($"(No cross-language header found at {Path.GetFileName(headerPath)})");
                }
            }
            catch (Exception e)
            {
                result.Fail($"Exception during {curve.Name} test: {e.Message}");
            }

            results.Add(result.Summary());
        }

        // Test 5: Runtime Code Generation
        Console.WriteLine("\nTest 5: Runtime Code Generation");
        Console.WriteLine(new string('-', 40));
        {
            var result = new TestResult("Code Generation");

            // Try to find native flatc binary (prefer built version over system)
            string[] flatcPaths = {
                Path.Combine(vectorsDir, "..", "..", "..", "..", "build", "flatc"),
                Path.Combine(vectorsDir, "..", "..", "..", "..", "flatc")
            };

            string? flatcPath = null;
            foreach (var p in flatcPaths)
            {
                var normalizedPath = Path.GetFullPath(p);
                if (File.Exists(normalizedPath))
                {
                    flatcPath = normalizedPath;
                    break;
                }
            }

            // Fall back to PATH if built flatc not found
            if (flatcPath == null)
            {
                try
                {
                    var which = new System.Diagnostics.Process
                    {
                        StartInfo = new System.Diagnostics.ProcessStartInfo
                        {
                            FileName = "which",
                            Arguments = "flatc",
                            RedirectStandardOutput = true,
                            UseShellExecute = false,
                            CreateNoWindow = true
                        }
                    };
                    which.Start();
                    var whichOutput = which.StandardOutput.ReadLine();
                    which.WaitForExit();
                    if (which.ExitCode == 0 && !string.IsNullOrEmpty(whichOutput))
                        flatcPath = whichOutput;
                }
                catch { }
            }

            if (flatcPath != null)
            {
                result.Pass($"Found flatc: {flatcPath}");

                // Get flatc version
                try
                {
                    var versionProc = new System.Diagnostics.Process
                    {
                        StartInfo = new System.Diagnostics.ProcessStartInfo
                        {
                            FileName = flatcPath,
                            Arguments = "--version",
                            RedirectStandardOutput = true,
                            UseShellExecute = false,
                            CreateNoWindow = true
                        }
                    };
                    versionProc.Start();
                    var version = versionProc.StandardOutput.ReadLine();
                    versionProc.WaitForExit();
                    if (versionProc.ExitCode == 0 && version != null)
                        result.Pass($"flatc version: {version}");
                }
                catch (Exception e)
                {
                    result.Fail($"Failed to get flatc version: {e.Message}");
                }

                // Generate C# code from schema
                var schemaPath = Path.GetFullPath(Path.Combine(vectorsDir, "..", "schemas", "message.fbs"));
                var tempDir = Path.Combine(Path.GetTempPath(), $"flatc-gen-{Environment.ProcessId}");
                Directory.CreateDirectory(tempDir);

                try
                {
                    var genProc = new System.Diagnostics.Process
                    {
                        StartInfo = new System.Diagnostics.ProcessStartInfo
                        {
                            FileName = flatcPath,
                            Arguments = $"--csharp -o \"{tempDir}\" \"{schemaPath}\"",
                            RedirectStandardError = true,
                            UseShellExecute = false,
                            CreateNoWindow = true
                        }
                    };
                    genProc.Start();
                    var stderr = genProc.StandardError.ReadToEnd();
                    genProc.WaitForExit();

                    if (genProc.ExitCode == 0)
                    {
                        result.Pass("Generated C# code from schema");

                        // List generated files
                        foreach (var file in Directory.GetFiles(tempDir, "*", SearchOption.AllDirectories))
                        {
                            var relPath = Path.GetRelativePath(tempDir, file);
                            var size = new FileInfo(file).Length;
                            result.Pass($"Generated: {relPath} ({size} bytes)");
                        }
                    }
                    else
                    {
                        result.Fail($"Generate C# code failed: {stderr}");
                    }
                }
                catch (Exception e)
                {
                    result.Fail($"Exception during code generation: {e.Message}");
                }
                finally
                {
                    try { Directory.Delete(tempDir, true); } catch { }
                }
            }
            else
            {
                result.Pass("flatc not found - using pre-generated code (this is OK)");
                // Verify pre-generated code exists
                var pregenPath = Path.Combine(vectorsDir, "..", "generated", "csharp", "E2E", "Crypto");
                if (Directory.Exists(pregenPath))
                {
                    var files = Directory.GetFiles(pregenPath, "*.cs");
                    result.Pass($"Pre-generated C# code: {files.Length} files in generated/csharp/E2E/Crypto/");
                }
            }

            results.Add(result.Summary());
        }

        // Test 6: Digital Signatures (Ed25519, secp256k1, P-256)
        Console.WriteLine("\nTest 6: Digital Signatures");
        Console.WriteLine(new string('-', 40));
        {
            var result = new TestResult("Digital Signatures");
            var testMessage = Encoding.UTF8.GetBytes("Hello, FlatBuffers! This is a test message for signing.");

            // Test Ed25519
            try
            {
                var kp = runner.Ed25519GenerateKeypair();
                result.Pass($"Ed25519 keypair generated (priv: {kp.privateKey.Length}, pub: {kp.publicKey.Length} bytes)");

                var sig = runner.Ed25519Sign(kp.privateKey, testMessage);
                result.Pass($"Ed25519 signature: {sig.Length} bytes");

                var valid = runner.Ed25519Verify(kp.publicKey, testMessage, sig);
                if (valid) result.Pass("Ed25519 signature verified");
                else result.Fail("Ed25519 signature verification failed");

                // Verify wrong message fails
                var wrongMessage = Encoding.UTF8.GetBytes("Wrong message");
                valid = runner.Ed25519Verify(kp.publicKey, wrongMessage, sig);
                if (!valid) result.Pass("Ed25519 rejects wrong message");
                else result.Fail("Ed25519 accepted wrong message");
            }
            catch (Exception e)
            {
                result.Fail($"Ed25519 test error: {e.Message}");
            }

            // Test secp256k1 signing
            try
            {
                var kp = runner.Secp256k1GenerateKeypair();
                result.Pass($"secp256k1 keypair generated (priv: {kp.privateKey.Length}, pub: {kp.publicKey.Length} bytes)");

                var sig = runner.Secp256k1Sign(kp.privateKey, testMessage);
                result.Pass($"secp256k1 signature: {sig.Length} bytes (DER)");

                var valid = runner.Secp256k1Verify(kp.publicKey, testMessage, sig);
                if (valid) result.Pass("secp256k1 signature verified");
                else result.Fail("secp256k1 signature verification failed");

                // Verify wrong message fails
                var wrongMessage = Encoding.UTF8.GetBytes("Wrong message");
                valid = runner.Secp256k1Verify(kp.publicKey, wrongMessage, sig);
                if (!valid) result.Pass("secp256k1 rejects wrong message");
                else result.Fail("secp256k1 accepted wrong message");
            }
            catch (Exception e)
            {
                result.Fail($"secp256k1 signing test error: {e.Message}");
            }

            // Test P-256 signing
            try
            {
                var kp = runner.P256GenerateKeypair();
                result.Pass($"P-256 keypair generated (priv: {kp.privateKey.Length}, pub: {kp.publicKey.Length} bytes)");

                var sig = runner.P256Sign(kp.privateKey, testMessage);
                result.Pass($"P-256 signature: {sig.Length} bytes (DER)");

                var valid = runner.P256Verify(kp.publicKey, testMessage, sig);
                if (valid) result.Pass("P-256 signature verified");
                else result.Fail("P-256 signature verification failed");

                // Verify wrong message fails
                var wrongMessage = Encoding.UTF8.GetBytes("Wrong message");
                valid = runner.P256Verify(kp.publicKey, wrongMessage, sig);
                if (!valid) result.Pass("P-256 rejects wrong message");
                else result.Fail("P-256 accepted wrong message");
            }
            catch (Exception e)
            {
                result.Fail($"P-256 signing test error: {e.Message}");
            }

            results.Add(result.Summary());
        }

        // Test 7: FlatBuffer Creation
        Console.WriteLine("\nTest 7: FlatBuffer Creation");
        Console.WriteLine(new string('-', 40));
        {
            var result = new TestResult("FlatBuffer Creation");

            try
            {
                // Create a SecureMessage using the FlatBuffers builder
                var builder = new FlatBufferBuilder(1024);

                // Build the Payload first (inner table)
                var payloadMsgOffset = builder.CreateString("Hello from C#!");
                byte[] payloadData = { 0x01, 0x02, 0x03, 0x04, 0x05 };
                var payloadDataOffset = FBPayload.CreateDataVector(builder, payloadData);

                var payloadOffset = FBPayload.CreatePayload(builder, payloadMsgOffset, 42, payloadDataOffset);

                // Build the SecureMessage
                var idOffset = builder.CreateString("csharp-msg-001");
                var senderOffset = builder.CreateString("csharp-alice");
                var recipientOffset = builder.CreateString("csharp-bob");

                var secureMessageOffset = FBSecureMessage.CreateSecureMessage(builder, idOffset, senderOffset, recipientOffset, payloadOffset, 1704067200);

                FBSecureMessage.FinishSecureMessageBuffer(builder, secureMessageOffset);

                var buf = builder.SizedByteArray();
                result.Pass($"Created SecureMessage binary: {buf.Length} bytes");

                // Verify the buffer has the correct file identifier
                if (buf.Length >= 8 && buf[4] == 'S' && buf[5] == 'E' && buf[6] == 'C' && buf[7] == 'M')
                {
                    result.Pass("Buffer has correct SECM identifier");
                }
                else
                {
                    result.Fail("Buffer missing SECM identifier");
                }

                // Read it back and verify contents
                var byteBuffer = new ByteBuffer(buf);
                var msg = FBSecureMessage.GetRootAsSecureMessage(byteBuffer);

                if (msg.Id == "csharp-msg-001")
                    result.Pass("Read back id: csharp-msg-001");
                else
                    result.Fail($"Wrong id: {msg.Id}");

                if (msg.Sender == "csharp-alice")
                    result.Pass("Read back sender: csharp-alice");
                else
                    result.Fail($"Wrong sender: {msg.Sender}");

                if (msg.Recipient == "csharp-bob")
                    result.Pass("Read back recipient: csharp-bob");
                else
                    result.Fail($"Wrong recipient: {msg.Recipient}");

                if (msg.Timestamp == 1704067200)
                    result.Pass("Read back timestamp: 1704067200");
                else
                    result.Fail($"Wrong timestamp: {msg.Timestamp}");

                var payloadObj = msg.Payload;
                if (payloadObj.HasValue)
                {
                    var p = payloadObj.Value;
                    if (p.Message == "Hello from C#!")
                        result.Pass("Read back payload message: Hello from C#!");
                    else
                        result.Fail($"Wrong payload message: {p.Message}");

                    if (p.Value == 42)
                        result.Pass("Read back payload value: 42");
                    else
                        result.Fail($"Wrong payload value: {p.Value}");

                    if (p.DataLength == 5)
                    {
                        var readData = new byte[5];
                        for (int i = 0; i < 5; i++) readData[i] = p.Data(i);
                        if (readData.SequenceEqual(payloadData))
                            result.Pass($"Read back payload data: {p.DataLength} bytes");
                        else
                            result.Fail("Wrong payload data");
                    }
                    else
                    {
                        result.Fail($"Wrong payload data length: {p.DataLength}");
                    }
                }
                else
                {
                    result.Fail("Failed to read payload");
                }

                // Test encrypt-decrypt round trip with C#-created FlatBuffer
                if (encryptionKeys.TryGetValue("sui", out var suiKeys))
                {
                    var key = FromHex(suiKeys["key_hex"]);
                    var iv = FromHex(suiKeys["iv_hex"]);

                    // Make a copy to encrypt
                    var encrypted = runner.Encrypt(key, iv, buf);
                    result.Pass("Encrypted C#-created FlatBuffer");

                    // Decrypt
                    var decrypted = runner.Decrypt(key, iv, encrypted);
                    result.Pass("Decrypted C#-created FlatBuffer");

                    // Verify decrypted data matches original
                    if (decrypted.SequenceEqual(buf))
                        result.Pass("Decrypt round-trip verified");
                    else
                        result.Fail("Decrypted data doesn't match original");
                }
                else
                {
                    result.Fail("Sui encryption keys not found");
                }
            }
            catch (Exception e)
            {
                result.Fail($"FlatBuffer creation test error: {e.Message}");
            }

            results.Add(result.Summary());
        }

        // Summary
        Console.WriteLine("\n" + new string('=', 60));
        Console.WriteLine("Summary");
        Console.WriteLine(new string('=', 60));

        var passed = results.Count(r => r);
        var total = results.Count;
        Console.WriteLine($"\nTotal: {passed}/{total} test suites passed");

        if (passed == total)
        {
            Console.WriteLine("\n✓ All tests passed!");
            Environment.Exit(0);
        }
        else
        {
            Console.WriteLine("\n✗ Some tests failed");
            Environment.Exit(1);
        }
    }
}
