/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efi.h>

#define SLOT_A 0

typedef struct {
        /* Metadata about the structure */
        uint8_t version;              // 0x1
        uint8_t upgrade_pending;      // Set to nonzero value by userspace if boot_efi has changed
        uint8_t boot_count;           // Incremented by bootloader when booting if upgrade_pending
        uint8_t max_boot_count;       // Maximum allowed unsuccessful boot count
        uint8_t active_slot;          // Zero -- a; Nonzero -- b
        uint8_t reserved;

        /* Paths of the unified kernel images */
        char16_t a_efi[256];          // L"\\EFI\\Linux\\linux_a.efi"
        char16_t b_efi[256];          // L"\\EFI\\Linux\\linux_b.efi"
} ABConfig;

bool get_ab_config(EFI_FILE *root_dir, ABConfig *config);

bool increment_boot_count(EFI_FILE *root_dir, ABConfig *config);
bool switch_active_slot(EFI_FILE *root_dir, ABConfig *config);
