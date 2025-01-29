//===-- msan_flags.inc ------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// MSan runtime flags.
//
//===----------------------------------------------------------------------===//
#ifndef MSAN_FLAG
# error "Define MSAN_FLAG prior to including this file!"
#endif

// MSAN_FLAG(Type, Name, DefaultValue, Description)
// See COMMON_FLAG in sanitizer_flags.inc for more details.

MSAN_FLAG(int, exit_code, -1,
          "DEPRECATED. Use exitcode from common flags instead.")
MSAN_FLAG(int, origin_history_size, 0, "")
MSAN_FLAG(int, origin_history_per_stack_limit, 0, "")
MSAN_FLAG(bool, poison_heap_with_zeroes, false, "")
MSAN_FLAG(bool, poison_stack_with_zeroes, false, "")
MSAN_FLAG(bool, poison_in_malloc, false, "")
MSAN_FLAG(bool, poison_in_free, false, "")
MSAN_FLAG(bool, poison_in_dtor, false, "")
MSAN_FLAG(bool, report_umrs, false, "")
MSAN_FLAG(bool, wrap_signals, true, "")
MSAN_FLAG(bool, print_stats, false, "")
MSAN_FLAG(bool, halt_on_error, false, "")
MSAN_FLAG(bool, atexit, true, "")
MSAN_FLAG(int, store_context_size, 0,
          "Like malloc_context_size, but for uninit stores.")
