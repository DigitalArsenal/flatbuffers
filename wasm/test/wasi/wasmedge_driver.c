/*
 * wasmedge_driver.c - hosts a WASI module in WasmEdge (C API) and serves a
 * line protocol on stdin/stdout, so test_flatc_wasi.mjs runs the same
 * scenarios under WasmEdge that it runs under Node's WASI.
 *
 *   call <export> [i32|i64 args...]  -> ok [results...] | trap <msg> | error <msg>
 *   write <ptr> <hex>                -> ok | error <msg>
 *   read <ptr> <len>                 -> ok <hex> | error <msg>
 *   quit
 *
 * Usage: wasmedge_driver <module.wasm>. Prints "ready" once instantiated.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wasmedge/wasmedge.h>

static WasmEdge_VMContext *vm;
static WasmEdge_MemoryInstanceContext *memory;

static int hexval(int c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static void reply_error(const char *kind, const char *msg) {
  printf("%s %s\n", kind, msg);
}

static void do_call(char *rest) {
  char *name = strtok(rest, " ");
  if (!name) return reply_error("error", "missing export name");
  WasmEdge_String fname = WasmEdge_StringCreateByCString(name);
  const WasmEdge_FunctionTypeContext *ftype = WasmEdge_VMGetFunctionType(vm, fname);
  if (!ftype) {
    WasmEdge_StringDelete(fname);
    return reply_error("error", "no such export");
  }
  uint32_t np = WasmEdge_FunctionTypeGetParametersLength(ftype);
  uint32_t nr = WasmEdge_FunctionTypeGetReturnsLength(ftype);
  WasmEdge_ValType ptypes[16], rtypes[4];
  WasmEdge_Value params[16], returns[4];
  if (np > 16 || nr > 4) {
    WasmEdge_StringDelete(fname);
    return reply_error("error", "signature too wide");
  }
  WasmEdge_FunctionTypeGetParameters(ftype, ptypes, np);
  WasmEdge_FunctionTypeGetReturns(ftype, rtypes, nr);
  for (uint32_t i = 0; i < np; i++) {
    char *arg = strtok(NULL, " ");
    if (!arg) {
      WasmEdge_StringDelete(fname);
      return reply_error("error", "too few arguments");
    }
    long long v = strtoll(arg, NULL, 10);
    if (WasmEdge_ValTypeIsI32(ptypes[i])) {
      params[i] = WasmEdge_ValueGenI32((int32_t)(uint32_t)v);
    } else if (WasmEdge_ValTypeIsI64(ptypes[i])) {
      params[i] = WasmEdge_ValueGenI64((int64_t)v);
    } else {
      WasmEdge_StringDelete(fname);
      return reply_error("error", "unsupported parameter type");
    }
  }
  if (strtok(NULL, " ")) {
    WasmEdge_StringDelete(fname);
    return reply_error("error", "too many arguments");
  }
  WasmEdge_Result res = WasmEdge_VMExecute(vm, fname, params, np, returns, nr);
  WasmEdge_StringDelete(fname);
  if (!WasmEdge_ResultOK(res)) {
    return reply_error("trap", WasmEdge_ResultGetMessage(res));
  }
  printf("ok");
  for (uint32_t i = 0; i < nr; i++) {
    if (WasmEdge_ValTypeIsI32(rtypes[i])) {
      printf(" %d", WasmEdge_ValueGetI32(returns[i]));
    } else if (WasmEdge_ValTypeIsI64(rtypes[i])) {
      printf(" %lld", (long long)WasmEdge_ValueGetI64(returns[i]));
    } else {
      printf(" ?");
    }
  }
  printf("\n");
}

static void do_write(char *rest) {
  char *ptr_s = strtok(rest, " ");
  char *hex = strtok(NULL, " ");
  if (!ptr_s) return reply_error("error", "missing pointer");
  size_t hexlen = hex ? strlen(hex) : 0;
  if (hexlen % 2) return reply_error("error", "odd hex length");
  size_t n = hexlen / 2;
  uint8_t *buf = malloc(n ? n : 1);
  for (size_t i = 0; i < n; i++) {
    int hi = hexval(hex[2 * i]), lo = hexval(hex[2 * i + 1]);
    if (hi < 0 || lo < 0) {
      free(buf);
      return reply_error("error", "bad hex");
    }
    buf[i] = (uint8_t)(hi << 4 | lo);
  }
  uint32_t ptr = (uint32_t)strtoul(ptr_s, NULL, 10);
  WasmEdge_Result res = WasmEdge_MemoryInstanceSetData(memory, buf, ptr, (uint32_t)n);
  free(buf);
  if (!WasmEdge_ResultOK(res)) return reply_error("error", WasmEdge_ResultGetMessage(res));
  printf("ok\n");
}

static void do_read(char *rest) {
  char *ptr_s = strtok(rest, " ");
  char *len_s = strtok(NULL, " ");
  if (!ptr_s || !len_s) return reply_error("error", "missing pointer or length");
  uint32_t ptr = (uint32_t)strtoul(ptr_s, NULL, 10);
  uint32_t n = (uint32_t)strtoul(len_s, NULL, 10);
  uint8_t *buf = malloc(n ? n : 1);
  WasmEdge_Result res = WasmEdge_MemoryInstanceGetData(memory, buf, ptr, n);
  if (!WasmEdge_ResultOK(res)) {
    free(buf);
    return reply_error("error", WasmEdge_ResultGetMessage(res));
  }
  static const char digits[] = "0123456789abcdef";
  fputs("ok ", stdout);
  for (uint32_t i = 0; i < n; i++) {
    putchar(digits[buf[i] >> 4]);
    putchar(digits[buf[i] & 15]);
  }
  putchar('\n');
  free(buf);
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s <module.wasm>\n", argv[0]);
    return 2;
  }
  /* WasmEdge logs traps to stdout, which would break the line protocol; the
   * trap message is reported through the "trap" reply instead. */
  WasmEdge_LogOff();
  WasmEdge_ConfigureContext *conf = WasmEdge_ConfigureCreate();
  WasmEdge_ConfigureAddHostRegistration(conf, WasmEdge_HostRegistration_Wasi);
  vm = WasmEdge_VMCreate(conf, NULL);
  WasmEdge_ModuleInstanceContext *wasi =
      WasmEdge_VMGetImportModuleContext(vm, WasmEdge_HostRegistration_Wasi);
  const char *wasi_args[] = {"flatc-wasi"};
  WasmEdge_ModuleInstanceInitWASI(wasi, wasi_args, 1, NULL, 0, NULL, 0);

  WasmEdge_Result res = WasmEdge_VMLoadWasmFromFile(vm, argv[1]);
  if (WasmEdge_ResultOK(res)) res = WasmEdge_VMValidate(vm);
  if (WasmEdge_ResultOK(res)) res = WasmEdge_VMInstantiate(vm);
  if (!WasmEdge_ResultOK(res)) {
    printf("error %s\n", WasmEdge_ResultGetMessage(res));
    return 1;
  }
  WasmEdge_String mem_name = WasmEdge_StringCreateByCString("memory");
  memory = WasmEdge_ModuleInstanceFindMemory(WasmEdge_VMGetActiveModule(vm), mem_name);
  WasmEdge_StringDelete(mem_name);
  if (!memory) {
    printf("error module exports no memory\n");
    return 1;
  }
  printf("ready\n");
  fflush(stdout);

  char *line = NULL;
  size_t cap = 0;
  ssize_t len;
  while ((len = getline(&line, &cap, stdin)) > 0) {
    if (line[len - 1] == '\n') line[len - 1] = '\0';
    char *rest = strchr(line, ' ');
    if (rest) *rest++ = '\0';
    else rest = line + strlen(line);
    if (!strcmp(line, "call")) do_call(rest);
    else if (!strcmp(line, "write")) do_write(rest);
    else if (!strcmp(line, "read")) do_read(rest);
    else if (!strcmp(line, "quit")) break;
    else reply_error("error", "unknown command");
    fflush(stdout);
  }
  free(line);
  WasmEdge_VMDelete(vm);
  WasmEdge_ConfigureDelete(conf);
  return 0;
}
