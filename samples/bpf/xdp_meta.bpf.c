/* This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include "vmlinux.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

struct xdp_meta_generic___btf {
	u32        btf_id;
};

SEC("xdp")
int xdp_meta_prog(struct xdp_md *ctx)
{
	struct xdp_meta_generic___btf *data_meta =
		(void *)(long)ctx->data_meta;
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	u32 *btf_id = (void *)((long)ctx->data - 4);
	struct ethhdr *eth = data;
	u64 nh_off;
	int id;
	long *value;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return XDP_DROP;

	if (data_meta + 1 > data)
		return XDP_DROP;

	id = bpf_core_type_id_kernel(struct xdp_meta_generic___btf);
	bpf_printk("id from libbpf %d, id from hints metadata %d\n", id, data_meta->btf_id);

	if (id && id == data_meta->btf_id)
		bpf_printk("hints match btf_id\n");

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
