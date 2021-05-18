
/* Copyright (c) 2021 Intel
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/btf.h>

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, long);
	__uint(max_entries, 256);
} packet_info SEC(".maps");

struct hints_hdr {
	__u32 timestamp;
};

BTF_XDP_USE_HINTS(struct hints_hdr);

SEC("xdp_hints_hash")
int xdp_hints_hash_prog(struct xdp_md *ctx)
{
	struct hints_hdr *meta = (struct hints_hdr *)(long)ctx->data_meta;
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	int rc = XDP_DROP;
	long *value;
	u32 key = 0;

	if (meta + 1 > data)
		return rc;

	if (data + 1 > data_end)
		return rc;

	value = bpf_map_lookup_elem(&packet_info, &key);
	if (value)
		*value = meta->timestamp;

	return rc;
}

char _license[] SEC("license") = "GPL";
