/*
 * Copyright 2026 Google Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Batching and range driver for he-batching-range.e2e.mjs. It encrypts and
// decrypts the registered known-answer set (docs/source/
// homomorphic_encryption.md, "Batching and Range") and prints every input and
// output as JSON; the E2E checks them exactly with BigInt.

#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <random>
#include <string>
#include <vector>

#include "flatbuffers/he_encryption.h"

using namespace flatbuffers::he;
using Clock = std::chrono::steady_clock;

extern "C" {
int32_t wasi_he_context_create_client(uint32_t poly_degree);
const uint8_t* wasi_he_encrypt_int64_vector(int32_t ctx_id,
                                            const int64_t* values,
                                            uint32_t count,
                                            uint32_t bound_bits,
                                            uint32_t* out_len);
int32_t wasi_he_last_error();
void wasi_he_context_destroy(int32_t ctx_id);
}

namespace {

std::string out;  // the JSON document

void Raw(const std::string& s) { out += s; }

std::string Str(const std::string& s) { return "\"" + s + "\""; }

std::string Num(double v) {
  char b[40];
  std::snprintf(b, sizeof b, "%.17g", v);
  return b;
}

WideInt Pow2(uint32_t k) {  // 2^k, k < 192
  WideInt w;
  w.magnitude[k / 64] = uint64_t{1} << (k % 64);
  return w;
}

WideInt Pow2Minus1(uint32_t k) {  // 2^k - 1, k <= 192
  WideInt w;
  for (uint32_t i = 0; i < k; ++i) w.magnitude[i / 64] |= uint64_t{1} << (i % 64);
  return w;
}

WideInt Neg(WideInt w) {
  w.negative = !w.IsZero() && !w.negative;
  return w;
}

WideInt RandomWide(std::mt19937_64& rng, uint32_t bits, bool negative) {
  WideInt w;
  for (uint32_t i = 0; i + 1 < bits; ++i) {
    if (rng() & 1) w.magnitude[i / 64] |= uint64_t{1} << (i % 64);
  }
  if (bits) w.magnitude[(bits - 1) / 64] |= uint64_t{1} << ((bits - 1) % 64);
  w.negative = negative && !w.IsZero();
  return w;
}

void WideArray(const char* key, const std::vector<WideInt>& v, size_t n) {
  Raw(Str(key) + ":[");
  for (size_t i = 0; i < n; ++i) Raw((i ? "," : "") + Str(v[i].ToString()));
  Raw("]");
}

void DoubleArray(const char* key, const std::vector<double>& v) {
  Raw(Str(key) + ":[");
  for (size_t i = 0; i < v.size(); ++i) Raw((i ? "," : "") + Num(v[i]));
  Raw("]");
}

// Runs fn; returns the refusal code name, or "none".
template <typename Fn>
std::string Code(const HEContext& ctx, Fn fn) {
  try {
    const std::vector<uint8_t> ct = fn();
    if (!ct.empty()) return "none";
    return HEErrorName(ctx.LastError().error);
  } catch (const HEException& e) {
    return HEErrorName(e.code());
  }
}

bool first_refusal = true;
void Refusal(const std::string& name, const std::string& code) {
  Raw(std::string(first_refusal ? "" : ",") + "{\"name\":" + Str(name) +
      ",\"code\":" + Str(code) + "}");
  first_refusal = false;
}

double Ms(Clock::time_point a, Clock::time_point b) {
  return std::chrono::duration<double, std::milli>(b - a).count();
}

}  // namespace

int main() {
  std::mt19937_64 rng(20261106);
  HEContext client = HEContext::CreateClient();
  if (!client.IsValid()) {
    std::printf("{\"error\":\"client context invalid\"}\n");
    return 2;
  }
  const std::vector<uint8_t> pk = client.GetPublicKey();
  const std::vector<uint8_t> rk = client.GetRelinKeys();
  HEContext server = HEContext::CreateServer(pk.data(), pk.size());
  if (!server.IsValid() || !server.SetRelinKeys(rk.data(), rk.size()).ok()) {
    std::printf("{\"error\":\"server context invalid\"}\n");
    return 2;
  }
  const size_t n = client.SlotCount();

  Raw("{\"polyModulusDegree\":" + std::to_string(client.GetPolyModulusDegree()));
  Raw(",\"slotCount\":" + std::to_string(n));
  Raw(",\"maxBoundBits\":" + std::to_string(kMaxBoundBits));
  Raw(",\"plainModuli\":[");
  const auto moduli = client.GetPlainModuli();
  for (size_t i = 0; i < moduli.size(); ++i) {
    Raw((i ? "," : "") + Str(std::to_string(moduli[i])));
  }
  Raw("]");

  // 1. Typed scalars.
  Raw(",\"typedScalars\":[");
  {
    bool first = true;
    auto row = [&](const char* type, const std::string& in, const std::string& o) {
      Raw(std::string(first ? "" : ",") + "{\"type\":" + Str(type) +
          ",\"in\":" + Str(in) + ",\"out\":" + Str(o) + "}");
      first = false;
    };
    const int64_t i64[] = {0, 1, -1, std::numeric_limits<int64_t>::max(),
                           -std::numeric_limits<int64_t>::max(),
                           std::numeric_limits<int64_t>::min()};
    for (int64_t v : i64) {
      const auto ct = client.EncryptInt64(v);
      row("int64", std::to_string(v),
          std::to_string(client.DecryptInt64(ct.data(), ct.size())));
    }
    {
      const auto ct = server.EncryptInt64(std::numeric_limits<int64_t>::min());
      row("int64-public-key", std::to_string(std::numeric_limits<int64_t>::min()),
          std::to_string(client.DecryptInt64(ct.data(), ct.size())));
    }
    const uint64_t u64 = std::numeric_limits<uint64_t>::max();
    const auto cu = client.EncryptUInt64(u64);
    row("uint64", std::to_string(u64),
        std::to_string(client.DecryptUInt64(cu.data(), cu.size())));
    for (int v : {-128, 127}) {
      const auto ct = client.EncryptInt8(static_cast<int8_t>(v));
      row("int8", std::to_string(v),
          std::to_string(client.DecryptInt8(ct.data(), ct.size())));
    }
    for (int32_t v : {std::numeric_limits<int32_t>::min(),
                      std::numeric_limits<int32_t>::max()}) {
      const auto ct = client.EncryptInt32(v);
      row("int32", std::to_string(v),
          std::to_string(client.DecryptInt32(ct.data(), ct.size())));
    }
    for (const WideInt& w : {Pow2Minus1(178), Neg(Pow2Minus1(178)), Pow2(177),
                             Neg(Pow2(177))}) {
      const auto ct = client.EncryptWide(w);
      row("wide", w.ToString(), client.DecryptWide(ct.data(), ct.size()).ToString());
    }
  }
  Raw("]");

  // 2. Wide known answers: +/-(2^k - 1), +/-2^(k-1), k = 1..178, one vector.
  {
    std::vector<WideInt> kat;
    for (uint32_t k = 1; k <= kMaxBoundBits; ++k) {
      kat.push_back(Pow2Minus1(k));
      kat.push_back(Neg(Pow2Minus1(k)));
      kat.push_back(Pow2(k - 1));
      kat.push_back(Neg(Pow2(k - 1)));
    }
    const auto ct = client.EncryptWideVector(kat, kMaxBoundBits);
    const auto dec = client.DecryptWideVector(ct.data(), ct.size());
    size_t rest_nonzero = 0;
    for (size_t i = kat.size(); i < dec.size(); ++i) rest_nonzero += !dec[i].IsZero();
    Raw(",\"wideKnownAnswers\":{");
    WideArray("in", kat, kat.size());
    Raw(",");
    WideArray("out", dec, kat.size());
    Raw(",\"unusedSlotsNonZero\":" + std::to_string(rest_nonzero) + "}");
  }

  // 3. Full slot vector: n distinct wide values including both bounds.
  double encrypt_ms = 0, decrypt_ms = 0;
  size_t ciphertext_bytes = 0;
  {
    std::vector<WideInt> v(n);
    for (size_t i = 0; i < n; ++i) {
      const uint32_t bits = 14 + static_cast<uint32_t>(rng() % (kMaxBoundBits - 13));
      v[i] = RandomWide(rng, bits, rng() & 1);
      v[i].magnitude[0] = (v[i].magnitude[0] & ~uint64_t{0x1fff}) | i;  // distinct
    }
    v[0] = Pow2Minus1(kMaxBoundBits);
    v[1] = Neg(Pow2Minus1(kMaxBoundBits));
    auto t0 = Clock::now();
    const auto ct = client.EncryptWideVector(v, kMaxBoundBits);
    auto t1 = Clock::now();
    const auto dec = client.DecryptWideVector(ct.data(), ct.size());
    auto t2 = Clock::now();
    encrypt_ms = Ms(t0, t1);
    decrypt_ms = Ms(t1, t2);
    ciphertext_bytes = ct.size();
    Raw(",\"wideSlots\":{");
    WideArray("in", v, n);
    Raw(",");
    WideArray("out", dec, n);
    Raw("}");

    std::vector<int64_t> iv(n);
    for (size_t i = 0; i < n; ++i) iv[i] = static_cast<int64_t>(rng());
    iv[0] = std::numeric_limits<int64_t>::min();
    iv[1] = std::numeric_limits<int64_t>::max();
    const auto ict = client.EncryptInt64Vector(iv);
    const auto idec = client.DecryptInt64Vector(ict.data(), ict.size());
    Raw(",\"int64Slots\":{\"in\":[");
    for (size_t i = 0; i < n; ++i) Raw((i ? "," : "") + Str(std::to_string(iv[i])));
    Raw("],\"out\":[");
    for (size_t i = 0; i < n; ++i) Raw((i ? "," : "") + Str(std::to_string(idec[i])));
    Raw("]}");
  }

  // 4. Fixed point: scales 2^0, 2^16, 2^40, full range, vector and scalar.
  Raw(",\"fixedPoint\":[");
  {
    const uint32_t log2_scales[] = {0, 16, 40};
    for (size_t si = 0; si < 3; ++si) {
      const uint64_t scale = uint64_t{1} << log2_scales[si];
      const double q = std::ldexp(1.0, -static_cast<int>(log2_scales[si]));
      const double top = std::ldexp(std::ldexp(1.0, 178) - std::ldexp(1.0, 125),
                                    -static_cast<int>(log2_scales[si]));
      std::vector<double> v = {top, -top, q, -q, 3 * q, -3 * q, 0.5 * q,
                               -0.5 * q, 1.5 * q, -2.5 * q, 0.0, 12345.678,
                               -98765.4321};
      for (int i = 0; i < 64; ++i) {
        const int e = static_cast<int>(rng() % 176) - static_cast<int>(log2_scales[si]);
        const double m = std::ldexp(static_cast<double>(rng() >> 11), -53);  // [0,1)
        v.push_back((rng() & 1 ? -1 : 1) * std::ldexp(m, e));
      }
      const auto ct = client.EncryptDoubleVector(v, scale, kMaxBoundBits);
      const auto dec = client.DecryptDoubleVector(ct.data(), ct.size(), scale);
      std::vector<double> got(dec.begin(), dec.begin() + v.size());
      std::vector<double> scalar_in = {top, -top, 3 * q, -2.5 * q};
      std::vector<double> scalar_out;
      for (double x : scalar_in) {
        const auto sct = client.EncryptDouble(x, scale, kMaxBoundBits);
        scalar_out.push_back(client.DecryptDouble(sct.data(), sct.size(), scale));
      }
      Raw(std::string(si ? "," : "") + "{\"log2Scale\":" +
          std::to_string(log2_scales[si]) + ",");
      DoubleArray("in", v);
      Raw(",");
      DoubleArray("out", got);
      Raw(",");
      DoubleArray("scalarIn", scalar_in);
      Raw(",");
      DoubleArray("scalarOut", scalar_out);
      Raw("}");
    }
  }
  Raw("]");

  // 5. Arithmetic at the bound, computed by the public-key context.
  int noise_after_multiply = 0;
  double multiply_ms = 0;
  {
    std::vector<WideInt> a(n), b(n), c(n), d(n);
    for (size_t i = 0; i < n; ++i) {
      a[i] = RandomWide(rng, 89, rng() & 1);
      b[i] = RandomWide(rng, 89, rng() & 1);
      c[i] = RandomWide(rng, 177, rng() & 1);
      d[i] = RandomWide(rng, 177, rng() & 1);
    }
    a[0] = Pow2Minus1(89);
    b[0] = Neg(Pow2Minus1(89));
    c[0] = Pow2Minus1(177);
    d[0] = Pow2Minus1(177);
    const auto ea = client.EncryptWideVector(a, 89);
    const auto eb = client.EncryptWideVector(b, 89);
    const auto ec = client.EncryptWideVector(c, 177);
    const auto ed = client.EncryptWideVector(d, 177);
    auto t0 = Clock::now();
    const auto prod = server.Multiply(ea, eb);
    multiply_ms = Ms(t0, Clock::now());
    const auto sum = server.Add(ec, ed);
    const auto diff = server.Sub(ec.data(), ec.size(), ed.data(), ed.size());
    const auto neg = server.Negate(ec.data(), ec.size());
    const int64_t p = -(int64_t{1} << 62);
    const auto mulp = server.MultiplyPlain(ea.data(), ea.size(), p);
    const auto addp = server.AddPlain(ea.data(), ea.size(), p);
    noise_after_multiply = client.NoiseBudget(prod.data(), prod.size());
    Raw(",\"arithmetic\":{\"plain\":" + Str(std::to_string(p)) +
        ",\"productBoundBits\":" +
        std::to_string(HEContext::CiphertextBoundBits(prod.data(), prod.size())) +
        ",\"sumBoundBits\":" +
        std::to_string(HEContext::CiphertextBoundBits(sum.data(), sum.size())) + ",");
    WideArray("a", a, n);
    Raw(",");
    WideArray("b", b, n);
    Raw(",");
    WideArray("c", c, n);
    Raw(",");
    WideArray("d", d, n);
    Raw(",");
    WideArray("product", client.DecryptWideVector(prod.data(), prod.size()), n);
    Raw(",");
    WideArray("sum", client.DecryptWideVector(sum.data(), sum.size()), n);
    Raw(",");
    WideArray("difference", client.DecryptWideVector(diff.data(), diff.size()), n);
    Raw(",");
    WideArray("negation", client.DecryptWideVector(neg.data(), neg.size()), n);
    Raw(",");
    WideArray("multiplyPlain", client.DecryptWideVector(mulp.data(), mulp.size()), n);
    Raw(",");
    WideArray("addPlain", client.DecryptWideVector(addp.data(), addp.size()), n);
    Raw("}");
  }

  // 6. Refusals.
  Raw(",\"refusals\":[");
  Refusal("wide +2^178", Code(client, [&] { return client.EncryptWide(Pow2(178)); }));
  Refusal("wide -2^178",
          Code(client, [&] { return client.EncryptWide(Neg(Pow2(178))); }));
  Refusal("vector slot above its declared bound", Code(client, [&] {
            return client.EncryptInt64Vector({1, int64_t{1} << 40}, 32);
          }));
  Refusal("declared bound 179",
          Code(client, [&] { return client.EncryptWideVector({WideInt()}, 179); }));
  {
    const auto x = client.EncryptWideVector({Pow2Minus1(100)}, 100);
    Refusal("multiply of two 100-bit bounds",
            Code(server, [&] { return server.Multiply(x, x); }));
    const auto y = client.EncryptWide(Pow2Minus1(178), 178);
    Refusal("add at the 178-bit bound", Code(server, [&] { return server.Add(y, y); }));
    const auto z = client.EncryptWideVector({WideInt::FromInt64(1)}, 170);
    Refusal("multiply plain past the bound", Code(server, [&] {
              return server.MultiplyPlain(z.data(), z.size(), int64_t{1} << 20);
            }));
    const auto w = client.EncryptWide(Pow2(63), 64);
    Refusal("DecryptInt64 of 2^63", Code(client, [&] {
              client.DecryptInt64(w.data(), w.size());
              return std::vector<uint8_t>{1};
            }));
    const auto e128 = client.EncryptInt64(128);
    Refusal("DecryptInt8 of 128", Code(client, [&] {
              client.DecryptInt8(e128.data(), e128.size());
              return std::vector<uint8_t>{1};
            }));
  }
  {
    // Small values, so the bound stays in range while the noise runs out.
    const auto one = client.EncryptWideVector({WideInt::FromInt64(1)}, 1);
    const auto sq = server.Multiply(one, one);
    const auto quad = server.Multiply(sq, sq);
    Refusal("decrypt after the noise budget is exhausted", Code(client, [&] {
              if (quad.empty()) return std::vector<uint8_t>{};
              client.DecryptWideVector(quad.data(), quad.size());
              return std::vector<uint8_t>{1};
            }));
  }
  Refusal("fixed point NaN", Code(client, [&] {
            return client.EncryptDouble(std::numeric_limits<double>::quiet_NaN());
          }));
  Refusal("fixed point infinity", Code(client, [&] {
            return client.EncryptDouble(std::numeric_limits<double>::infinity());
          }));
  Refusal("fixed point 2^178", Code(client, [&] {
            return client.EncryptDouble(std::ldexp(1.0, 178), 1, kMaxBoundBits);
          }));
  Refusal("fixed point scale 3",
          Code(client, [&] { return client.EncryptDouble(1.0, 3); }));
  Refusal("n + 1 values", Code(client, [&] {
            return client.EncryptInt64Vector(std::vector<int64_t>(n + 1, 0));
          }));
  Refusal("poly modulus degree 4096",
          HEContext::CreateClient(4096).IsValid() ? "none" : "kInvalidContext");
  {
    const int32_t id = wasi_he_context_create_client(0);
    const int64_t values[] = {300};
    uint32_t len = 0;
    const uint8_t* p = wasi_he_encrypt_int64_vector(id, values, 1, 8, &len);
    Refusal("wasi value above its declared bound",
            p ? "none" : HEErrorName(static_cast<HEError>(wasi_he_last_error())));
    wasi_he_context_destroy(id);
  }
  Raw("]");

  Raw(",\"measured\":{\"encryptMsPerCiphertext\":" + Num(encrypt_ms) +
      ",\"decryptMsPerCiphertext\":" + Num(decrypt_ms) +
      ",\"multiplyMs\":" + Num(multiply_ms) +
      ",\"ciphertextBytes\":" + std::to_string(ciphertext_bytes) +
      ",\"noiseBudgetBitsAfterMultiply\":" + std::to_string(noise_after_multiply) +
      "}}");
  std::fwrite(out.data(), 1, out.size(), stdout);
  std::fputc('\n', stdout);
  return 0;
}
