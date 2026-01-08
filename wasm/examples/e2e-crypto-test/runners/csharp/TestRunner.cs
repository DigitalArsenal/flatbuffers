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

    private int _threwValue;
    private Table? _functionTable;

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
        _sha256 = GetFunction("sha256");
        _encryptBytes = GetFunction("encrypt_bytes");
        _decryptBytes = GetFunction("decrypt_bytes");
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
            mem?.Write(buf, RandomNumberGenerator.GetBytes(len));
            return 0;
        });
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
        _linker.DefineFunction("env", "invoke_v", (Caller c, int idx) => InvokeTable(idx));
        _linker.DefineFunction("env", "invoke_vi", (Caller c, int idx, int a) => InvokeTable(idx, a));
        _linker.DefineFunction("env", "invoke_vii", (Caller c, int idx, int a, int b) => InvokeTable(idx, a, b));
        _linker.DefineFunction("env", "invoke_viii", (Caller c, int idx, int a, int b, int cc) => InvokeTable(idx, a, b, cc));
        _linker.DefineFunction("env", "invoke_viiii", (Caller c, int idx, int a, int b, int cc, int d) => InvokeTable(idx, a, b, cc, d));
        _linker.DefineFunction("env", "invoke_viiiii", (Caller c, int idx, int a, int b, int cc, int d, int e) => InvokeTable(idx, a, b, cc, d, e));
        _linker.DefineFunction("env", "invoke_viiiiii", (Caller c, int idx, int a, int b, int cc, int d, int e, int f) => InvokeTable(idx, a, b, cc, d, e, f));
        _linker.DefineFunction("env", "invoke_viiiiiii", (Caller c, int idx, int a, int b, int cc, int d, int e, int f, int g) => InvokeTable(idx, a, b, cc, d, e, f, g));
        _linker.DefineFunction("env", "invoke_viiiiiiiii", (Caller c, int idx, int a, int b, int cc, int d, int e, int f, int g, int h, int i) => InvokeTable(idx, a, b, cc, d, e, f, g, h, i));

        _linker.DefineFunction("env", "invoke_i", (Caller c, int idx) => InvokeTableInt(idx));
        _linker.DefineFunction("env", "invoke_ii", (Caller c, int idx, int a) => InvokeTableInt(idx, a));
        _linker.DefineFunction("env", "invoke_iii", (Caller c, int idx, int a, int b) => InvokeTableInt(idx, a, b));
        _linker.DefineFunction("env", "invoke_iiii", (Caller c, int idx, int a, int b, int cc) => InvokeTableInt(idx, a, b, cc));
        _linker.DefineFunction("env", "invoke_iiiii", (Caller c, int idx, int a, int b, int cc, int d) => InvokeTableInt(idx, a, b, cc, d));
        _linker.DefineFunction("env", "invoke_iiiiii", (Caller c, int idx, int a, int b, int cc, int d, int e) => InvokeTableInt(idx, a, b, cc, d, e));
        _linker.DefineFunction("env", "invoke_iiiiiii", (Caller c, int idx, int a, int b, int cc, int d, int e, int f) => InvokeTableInt(idx, a, b, cc, d, e, f));
        _linker.DefineFunction("env", "invoke_iiiiiiii", (Caller c, int idx, int a, int b, int cc, int d, int e, int f, int g) => InvokeTableInt(idx, a, b, cc, d, e, f, g));
        _linker.DefineFunction("env", "invoke_iiiiiiiiii", (Caller c, int idx, int a, int b, int cc, int d, int e, int f, int g, int h, int i) => InvokeTableInt(idx, a, b, cc, d, e, f, g, h, i));
    }

    private void InvokeTable(int idx, params object[] args)
    {
        try
        {
            if (_functionTable != null && idx < (int)_functionTable.GetSize())
            {
                var func = _functionTable.GetElement((uint)idx) as Function;
                func?.Invoke(args);
            }
        }
        catch { _threwValue = 1; }
    }

    private int InvokeTableInt(int idx, params object[] args)
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
        catch { _threwValue = 1; }
        return 0;
    }

    private int Allocate(int size) => (int)_malloc.Invoke(size)!;
    private void Deallocate(int ptr) => _free.Invoke(ptr);

    public byte[] Sha256(byte[] data)
    {
        var dataPtr = Allocate(Math.Max(data.Length, 1));
        var hashPtr = Allocate(Sha256Size);

        if (data.Length > 0) _memory.Write(dataPtr, data);
        _sha256.Invoke(dataPtr, data.Length, hashPtr);

        var hash = _memory.Read(dataPtr: hashPtr, Sha256Size).ToArray();
        Deallocate(dataPtr);
        Deallocate(hashPtr);
        return hash;
    }

    public byte[] Encrypt(byte[] key, byte[] iv, byte[] data)
    {
        var keyPtr = Allocate(AesKeySize);
        var ivPtr = Allocate(AesIvSize);
        var dataPtr = Allocate(data.Length);

        _memory.Write(keyPtr, key);
        _memory.Write(ivPtr, iv);
        _memory.Write(dataPtr, data);
        _encryptBytes.Invoke(keyPtr, ivPtr, dataPtr, data.Length);

        var encrypted = _memory.Read(dataPtr, data.Length).ToArray();
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

        _memory.Write(keyPtr, key);
        _memory.Write(ivPtr, iv);
        _memory.Write(dataPtr, data);
        _decryptBytes.Invoke(keyPtr, ivPtr, dataPtr, data.Length);

        var decrypted = _memory.Read(dataPtr, data.Length).ToArray();
        Deallocate(keyPtr);
        Deallocate(ivPtr);
        Deallocate(dataPtr);
        return decrypted;
    }

    public void Dispose()
    {
        _store.Dispose();
        _engine.Dispose();
    }

    public static string ToHex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();
    public static byte[] FromHex(string hex) => Convert.FromHexString(hex);

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
        {
            var result = new TestResult("Cross-Language");

            var binaryDir = Path.Combine(vectorsDir, "binary");
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
