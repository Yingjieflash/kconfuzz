// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is included into executor and C reproducers and can be used to add
// non-mainline pseudo-syscalls and to provide some other extension points
// w/o changing any other files. See common_ext_example.h for an example implementation.

// Pseudo-syscalls defined in this file should start with syz_ext_.

// This file can also define SYZ_HAVE_SETUP_EXT to 1 and provide
// void setup_ext() function that will be called during VM setup.

// This file can also define SYZ_HAVE_SETUP_EXT_TEST to 1 and provide
// void setup_ext_test() function that will be called during setup of each test process.

// KConfuzz executor-side runtime config adjustment. These helpers are driven
// only by executor input instructions, not by startup hooks or external files.

#if GOOS_linux
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define KCONFUZZ_CONFIG_FLAG_NO_RESTORE 1
#define KCONFUZZ_CONFIG_FLAG_FLIP 2

static const char kKConfuzzLogFile[] = "/tmp/syz-kconfuzz-config-actions.log";
static const char kKConfuzzHostLogFile[] = "/proc/1/root/tmp/syz-kconfuzz-config-actions.log";

struct kconfuzz_runtime_config_entry {
	const char* name;
	const char* proc_path;
	const char* const* values;
	uint32_t value_count;
};

#include "executor/kconfuzz_runtime_configs.gen.h"

static char kconfuzz_saved_values[KCONFUZZ_CFG_COUNT][512];
static bool kconfuzz_saved_valid[KCONFUZZ_CFG_COUNT];
static uint32_t kconfuzz_saved_order[KCONFUZZ_CFG_COUNT];
static uint32_t kconfuzz_saved_count;

static bool kconfuzz_is_space(char ch)
{
	return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}

static void kconfuzz_trim(char* str)
{
	size_t len = strlen(str);
	while (len > 0 && kconfuzz_is_space(str[len - 1])) {
		str[len - 1] = 0;
		len--;
	}
	char* start = str;
	while (*start && kconfuzz_is_space(*start))
		start++;
	if (start != str)
		memmove(str, start, strlen(start) + 1);
}

static void kconfuzz_write_log_file(const char* file, const char* buf)
{
	int fd = open(file, O_WRONLY | O_CREAT | O_APPEND, 0644);
	if (fd == -1)
		return;
	ssize_t n1 = write(fd, buf, strlen(buf));
	ssize_t n2 = write(fd, "\n", 1);
	(void)n1;
	(void)n2;
	close(fd);
}

static void kconfuzz_log(const char* fmt, ...)
{
	if (!flag_debug)
		return;
	char buf[2048];
	va_list args;
	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);
	debug("kconfuzz: %s\n", buf);
	kconfuzz_write_log_file(kKConfuzzLogFile, buf);
	kconfuzz_write_log_file(kKConfuzzHostLogFile, buf);
}

static bool kconfuzz_readback(const char* file, char* out, size_t out_size)
{
	int fd = open(file, O_RDONLY);
	if (fd == -1) {
		snprintf(out, out_size, "READ_ERROR:%d", errno);
		return false;
	}
	ssize_t n = read(fd, out, out_size - 1);
	close(fd);
	if (n < 0) {
		snprintf(out, out_size, "READ_ERROR:%d", errno);
		return false;
	}
	out[n] = 0;
	kconfuzz_trim(out);
	return true;
}

static int kconfuzz_value_index(const struct kconfuzz_runtime_config_entry* entry, const char* value)
{
	for (uint32_t i = 0; i < entry->value_count; i++) {
		if (!strcmp(entry->values[i], value))
			return i;
	}
	return -1;
}

static void kconfuzz_apply_config_action(uint64 param_id, uint64 value_id, uint64 flags)
{
	if (param_id >= KCONFUZZ_CFG_COUNT) {
		kconfuzz_log("status=bad_param param_id=%llu value_id=%llu", param_id, value_id);
		return;
	}
	const struct kconfuzz_runtime_config_entry* entry = &kconfuzz_runtime_configs[param_id];
	if (!(flags & KCONFUZZ_CONFIG_FLAG_FLIP) && value_id >= entry->value_count) {
		kconfuzz_log("status=bad_value param=%s param_id=%llu value_id=%llu",
			     entry->name, param_id, value_id);
		return;
	}
	char before[512];
	before[0] = 0;
	if (!(flags & KCONFUZZ_CONFIG_FLAG_NO_RESTORE) && !kconfuzz_saved_valid[param_id]) {
		if (kconfuzz_readback(entry->proc_path, kconfuzz_saved_values[param_id],
				      sizeof(kconfuzz_saved_values[param_id]))) {
			kconfuzz_saved_valid[param_id] = true;
			if (kconfuzz_saved_count < KCONFUZZ_CFG_COUNT)
				kconfuzz_saved_order[kconfuzz_saved_count++] = param_id;
		} else {
			kconfuzz_log("status=save_failed param=%s path=%s", entry->name, entry->proc_path);
		}
	}
	uint64 selected_value_id = value_id;
	if (flags & KCONFUZZ_CONFIG_FLAG_FLIP) {
		if (kconfuzz_readback(entry->proc_path, before, sizeof(before))) {
			int index = kconfuzz_value_index(entry, before);
			if (index >= 0) {
				selected_value_id = (uint64)((index + 1) % entry->value_count);
			} else if (selected_value_id >= entry->value_count) {
				selected_value_id = 0;
			}
		} else if (selected_value_id >= entry->value_count) {
			selected_value_id = 0;
		}
	}
	if (selected_value_id >= entry->value_count) {
		kconfuzz_log("status=bad_value param=%s param_id=%llu value_id=%llu flags=%llu",
			     entry->name, param_id, value_id, flags);
		return;
	}
	const char* value = entry->values[selected_value_id];
	if (!write_file(entry->proc_path, "%s", value)) {
		kconfuzz_log("status=write_failed param=%s path=%s requested=%s errno=%d",
			     entry->name, entry->proc_path, value, errno);
		return;
	}
	if (flag_debug) {
		char actual[512];
		kconfuzz_readback(entry->proc_path, actual, sizeof(actual));
		kconfuzz_log("status=applied param=%s path=%s requested=%s actual=%s before=%s flags=%llu",
			     entry->name, entry->proc_path, value, actual, before, flags);
	}
}

static void kconfuzz_restore_config_actions()
{
	while (kconfuzz_saved_count > 0) {
		uint32_t param_id = kconfuzz_saved_order[--kconfuzz_saved_count];
		if (param_id >= KCONFUZZ_CFG_COUNT || !kconfuzz_saved_valid[param_id])
			continue;
		const struct kconfuzz_runtime_config_entry* entry = &kconfuzz_runtime_configs[param_id];
		if (!write_file(entry->proc_path, "%s", kconfuzz_saved_values[param_id])) {
			kconfuzz_log("status=restore_failed param=%s path=%s value=%s errno=%d",
				     entry->name, entry->proc_path, kconfuzz_saved_values[param_id], errno);
		} else {
			kconfuzz_log("status=restored param=%s path=%s value=%s",
				     entry->name, entry->proc_path, kconfuzz_saved_values[param_id]);
		}
		kconfuzz_saved_valid[param_id] = false;
		kconfuzz_saved_values[param_id][0] = 0;
	}
}
#else
static void kconfuzz_apply_config_action(uint64 param_id, uint64 value_id, uint64 flags)
{
	(void)param_id;
	(void)value_id;
	(void)flags;
}

static void kconfuzz_restore_config_actions()
{
}
#endif
