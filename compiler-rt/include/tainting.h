#ifndef TAINTING_H
#define TAINTING_H

#include <cstdint>
#include <cstdio>
#include <cstring>

class Tainting {
  __attribute__((no_sanitize("memory", "dataflow")))
  static char *toShadowAddr(void *ptr) {
    return (char *)((intptr_t)(ptr) ^ 0x500000000000);
  }

public:
  __attribute__((no_sanitize("memory", "dataflow")))
  static void taintPtr(void *ptr, unsigned size) {
    memset(toShadowAddr(ptr), 0xff, size);
  }

  __attribute__((no_sanitize("memory", "dataflow")))
  static void untaintPtr(void *ptr, unsigned size) {
    memset(toShadowAddr(ptr), 0x0, size);
  }

  __attribute__((no_sanitize("memory", "dataflow")))
  static void taintBits(uint8_t *byte, uint8_t lbl) {
    memset(toShadowAddr(byte), lbl, 1);
  }

  [[nodiscard]]
  __attribute__((no_sanitize("memory", "dataflow")))
  static bool check(void *ptr, unsigned size) {
    char *addr = toShadowAddr(ptr);
    char *end = addr + size;
    for (; addr < end; ++addr) {
      if (*addr != 0)
        return true;
    }
    return false;
  }
};

#endif // TAINTING_H
