/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
//#include <efilib.h>

#include "sha256.h"
#include "slot.h"
#include "util.h"

static EFI_STATUS read_file(EFI_FILE *dir, const uint16_t *name, size_t size, uint8_t *buf) {
        _cleanup_(file_closep) EFI_FILE *handle = NULL;
        EFI_STATUS err;

        err = dir->Open(dir, &handle, (char16_t*) name, EFI_FILE_MODE_READ, 0ULL);
        if (err != EFI_SUCCESS)
                return err;

        err = handle->Read(handle, &size, (void*) buf);
        if (err != EFI_SUCCESS)
                return err;

        return err;
}

static EFI_STATUS write_file(EFI_FILE *dir, const uint16_t *name, size_t size, uint8_t *buf) {
        _cleanup_(file_closep) EFI_FILE *handle = NULL;
        EFI_STATUS err;

        err = dir->Open(dir, &handle, (char16_t*) name, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE, 0ULL);
        if (err != EFI_SUCCESS) {
                return err;
        }

        err = handle->Write(handle, &size, (void*) buf);
        if (err != EFI_SUCCESS) {
                return err;
        }

        return err;
}

static EFI_STATUS hash_and_write_file(EFI_FILE *dir, const uint16_t *name, const uint16_t *sum_name, size_t size, uint8_t *buf) {
        struct sha256_ctx ctx;
        uint8_t hash[32];
        EFI_STATUS err;

        sha256_init_ctx(&ctx);
        sha256_process_bytes(buf, size, &ctx);
        sha256_finish_ctx(&ctx, hash);

        err = write_file(dir, name, size, buf);
        if (err != EFI_SUCCESS)
                return err;

        err = write_file(dir, sum_name, 32, (uint8_t *) &hash);
        if (err != EFI_SUCCESS)
                return err;

        return err;
}

static bool validate_sha256sum(const uint8_t *buf, size_t size, uint8_t sum[32]) {
        struct sha256_ctx ctx;
        uint8_t hash[32];

        sha256_init_ctx(&ctx);
        sha256_process_bytes(buf, size, &ctx);
        sha256_finish_ctx(&ctx, hash);

        return memcmp(sum, hash, 32) == 0;
}

static bool write_config(EFI_FILE *root_dir, ABConfig *config) {
        EFI_STATUS err;

        err = hash_and_write_file(root_dir, L"\\loader\\main\\config", L"\\loader\\main\\config.sha256", sizeof(ABConfig), (uint8_t *) config);
        if (err != EFI_SUCCESS) {
                printf("Couldn't write config_a!\n");
                BS->Stall(3 * 1000 * 1000);
                return false;
        }

        err = hash_and_write_file(root_dir, L"\\loader\\backup\\config", L"\\loader\\backup\\config.sha256", sizeof(ABConfig), (uint8_t *) config);
        if (err != EFI_SUCCESS) {
                printf("Couldn't write config_b!\n");
                BS->Stall(3 * 1000 * 1000);
                return false;
        }

        return true;
}

bool get_ab_config(EFI_FILE *root_dir, ABConfig *config) {
        ABConfig config_a, config_b;
        uint8_t sum_a[32], sum_b[32];
        bool a_valid, b_valid;
        EFI_STATUS err_a, err_b;

        err_a = read_file(root_dir, L"\\loader\\main\\config", sizeof(config_a), (uint8_t *) &config_a);
        err_b = read_file(root_dir, L"\\loader\\backup\\config", sizeof(config_b), (uint8_t *) &config_b);

        if (err_a != EFI_SUCCESS && err_b != EFI_SUCCESS) {
                /* No readable boot slots detected. Quiet error. */
                return false;
        }

        err_a = read_file(root_dir, L"\\loader\\main\\config.sha256", sizeof(sum_a), (uint8_t *) &sum_a);
        err_b = read_file(root_dir, L"\\loader\\backup\\config.sha256", sizeof(sum_b), (uint8_t *) &sum_b);

        if (err_a != EFI_SUCCESS && err_b != EFI_SUCCESS) {
                printf("Boot slots detected but no checksums present\n");
                return false;
        }

        a_valid = validate_sha256sum((uint8_t *) &config_a, sizeof(config_a), sum_a);
        b_valid = validate_sha256sum((uint8_t *) &config_b, sizeof(config_b), sum_b);

        if (!a_valid && !b_valid) {
                printf("Boot slots detected but all checksums invalid\n");
                BS->Stall(3 * 1000 * 1000);
                return false;
        }

        // If both config slots are valid but are not equal, assume B was
        // interrupted in the process of writing and recreate it from A.
        if (a_valid && b_valid && memcmp(&config_a, &config_b, sizeof(config_a)) != 0) {
                b_valid = false;
        }

        if (a_valid && !b_valid) {
                printf("Recovering config B from config A\n");

                memcpy(&config_b, &config_a, sizeof(config_a));
                memcpy(&sum_b, &sum_a, sizeof(sum_a));

                write_file(root_dir, L"\\loader\\backup\\config", sizeof(config_a), (uint8_t *) &config_b);
                write_file(root_dir, L"\\loader\\backup\\config.sha256", sizeof(sum_b), (uint8_t *) &sum_b);

                b_valid = true;
        }

        if (b_valid && !a_valid) {
                printf("Recovering config A from config B\n");

                memcpy(&config_a, &config_b, sizeof(config_b));
                memcpy(&sum_a, &sum_b, sizeof(sum_b));

                write_file(root_dir, L"\\loader\\main\\config", sizeof(config_a), (uint8_t *) &config_a);
                write_file(root_dir, L"\\loader\\main\\config.sha256", sizeof(sum_a), (uint8_t *) &sum_a);

                a_valid = true;
        }

        *config = config_a;
        return true;
}

bool increment_boot_count(EFI_FILE *root_dir, ABConfig *config) {
        if (config->boot_count >= config->max_boot_count) {
                printf("Boot count already at max, not incrementing!\n");
                return false;
        }

        config->boot_count++;

        return write_config(root_dir, config);
}

bool switch_active_slot(EFI_FILE *root_dir, ABConfig *config) {
        config->active_slot = !config->active_slot;
        config->upgrade_pending = false;
        config->boot_count = 0;

        return write_config(root_dir, config);
}
