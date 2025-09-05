/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efilib.h>

#include "sha256.h"
#include "slot.h"
#include "util.h"

static EFI_STATUS read_file(EFI_FILE *dir, const CHAR16 *name, UINTN size, UINT8 *buf) {
        _cleanup_(FileHandleClosep) EFI_FILE *handle = NULL;
        EFI_STATUS err;

        err = uefi_call_wrapper(dir->Open, 5, dir, &handle, (CHAR16 *) name, EFI_FILE_MODE_READ, 0ULL);
        if (EFI_ERROR(err))
                return err;

        err = uefi_call_wrapper(handle->Read, 3, handle, &size, (CHAR8 *) buf);
        if (EFI_ERROR(err))
                return err;

        return err;
}

static EFI_STATUS write_file(EFI_FILE *dir, const CHAR16 *name, UINTN size, UINT8 *buf) {
        _cleanup_(FileHandleClosep) EFI_FILE *handle = NULL;
        EFI_STATUS err;

        err = uefi_call_wrapper(dir->Open, 5, dir, &handle, (CHAR16 *) name, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE, 0ULL);
        if (EFI_ERROR(err)) {
                return err;
        }

        err = uefi_call_wrapper(handle->Write, 3, handle, &size, (CHAR8 *) buf);
        if (EFI_ERROR(err)) {
                return err;
        }

        return err;
}

static EFI_STATUS hash_and_write_file(EFI_FILE *dir, const CHAR16 *name, const CHAR16 *sum_name, UINTN size, UINT8 *buf) {
        struct sha256_ctx ctx;
        UINT8 hash[32];
        EFI_STATUS err;

        sha256_init_ctx(&ctx);
        sha256_process_bytes(buf, size, &ctx);
        sha256_finish_ctx(&ctx, &hash);

        err = write_file(dir, name, size, buf);
        if (EFI_ERROR(err))
                return err;

        err = write_file(dir, sum_name, 32, (UINT8 *) &hash);
        if (EFI_ERROR(err))
                return err;

        return err;
}

static BOOLEAN validate_sha256sum(const UINT8 *buf, UINTN size, UINT8 sum[32]) {
        struct sha256_ctx ctx;
        UINT8 hash[32];

        sha256_init_ctx(&ctx);
        sha256_process_bytes(buf, size, &ctx);
        sha256_finish_ctx(&ctx, &hash);

        return CompareMem(sum, hash, 32) == 0;
}

static BOOLEAN write_config(EFI_FILE *root_dir, ABConfig *config) {
        EFI_STATUS err;

        err = hash_and_write_file(root_dir, L"\\loader\\main\\config", L"\\loader\\main\\config.sha256", sizeof(ABConfig), (UINT8 *) config);
        if (EFI_ERROR(err)) {
                Print(L"Couldn't write config_a!\n");
                uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
                return FALSE;
        }

        err = hash_and_write_file(root_dir, L"\\loader\\backup\\config", L"\\loader\\backup\\config.sha256", sizeof(ABConfig), (UINT8 *) config);
        if (EFI_ERROR(err)) {
                Print(L"Couldn't write config_b!\n");
                uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
                return FALSE;
        }

        return TRUE;
}

BOOLEAN get_ab_config(EFI_FILE *root_dir, ABConfig *config) {
        ABConfig config_a, config_b;
        UINT8 sum_a[32], sum_b[32];
        BOOLEAN a_valid, b_valid;
        EFI_STATUS err_a, err_b;

        err_a = read_file(root_dir, L"\\loader\\main\\config", sizeof(config_a), (UINT8 *) &config_a);
        err_b = read_file(root_dir, L"\\loader\\backup\\config", sizeof(config_b), (UINT8 *) &config_b);

        if (EFI_ERROR(err_a) && EFI_ERROR(err_b)) {
                /* No readable boot slots detected. Quiet error. */
                return FALSE;
        }

        err_a = read_file(root_dir, L"\\loader\\main\\config.sha256", sizeof(sum_a), (UINT8 *) &sum_a);
        err_b = read_file(root_dir, L"\\loader\\backup\\config.sha256", sizeof(sum_b), (UINT8 *) &sum_b);

        if (EFI_ERROR(err_a) && EFI_ERROR(err_b)) {
                Print(L"Boot slots detected but no checksums present\n");
                return FALSE;
        }

        a_valid = validate_sha256sum((UINT8 *) &config_a, sizeof(config_a), sum_a);
        b_valid = validate_sha256sum((UINT8 *) &config_b, sizeof(config_b), sum_b);

        if (!a_valid && !b_valid) {
                Print(L"Boot slots detected but all checksums invalid\n");
                uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
                return FALSE;
        }

        // If both config slots are valid but are not equal, assume B was
        // interrupted in the process of writing and recreate it from A.
        if (a_valid && b_valid && CompareMem(&config_a, &config_b, sizeof(config_a)) != 0) {
                b_valid = FALSE;
        }

        if (a_valid && !b_valid) {
                Print(L"Recovering config B from config A\n");

                CopyMem(&config_b, &config_a, sizeof(config_a));
                CopyMem(&sum_b, &sum_a, sizeof(sum_a));

                write_file(root_dir, L"\\loader\\backup\\config", sizeof(config_a), (UINT8 *) &config_b);
                write_file(root_dir, L"\\loader\\backup\\config.sha256", sizeof(sum_b), (UINT8 *) &sum_b);

                b_valid = TRUE;
        }

        if (b_valid && !a_valid) {
                Print(L"Recovering config A from config B\n");

                CopyMem(&config_a, &config_b, sizeof(config_b));
                CopyMem(&sum_a, &sum_b, sizeof(sum_b));

                write_file(root_dir, L"\\loader\\main\\config", sizeof(config_a), (UINT8 *) &config_a);
                write_file(root_dir, L"\\loader\\main\\config.sha256", sizeof(sum_a), (UINT8 *) &sum_a);

                a_valid = TRUE;
        }

        *config = config_a;
        return TRUE;
}

BOOLEAN increment_boot_count(EFI_FILE *root_dir, ABConfig *config) {
        if (config->boot_count >= config->max_boot_count) {
                Print(L"Boot count already at max, not incrementing!\n");
                return FALSE;
        }

        config->boot_count++;

        return write_config(root_dir, config);
}

BOOLEAN switch_active_slot(EFI_FILE *root_dir, ABConfig *config) {
        config->active_slot = !config->active_slot;
        config->upgrade_pending = FALSE;
        config->boot_count = 0;

        return write_config(root_dir, config);
}
