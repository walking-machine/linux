#include "ice.h"
#include "ice_hints_btf.h"

#include <linux/bpf.h>
#include <linux/btf.h>
#include <uapi/linux/btf.h>

#define BTF_INFO_ENC(kind, kind_flag, vlen) \
        ((!!(kind_flag) << 31) | ((kind) << 24) | ((vlen) & BTF_MAX_VLEN))

#define BTF_TYPE_ENC(name, info, size_or_type) \
        (name), (info), (size_or_type)

#define BTF_INT_ENC(encoding, bits_offset, nr_bits) \
        ((encoding) << 24 | (bits_offset) << 16 | (nr_bits))

#define BTF_TYPE_INT_ENC(name, encoding, bits_offset, bits, sz) \
        BTF_TYPE_ENC(name, BTF_INFO_ENC(BTF_KIND_INT, 0, 0), sz),       \
        BTF_INT_ENC(encoding, bits_offset, bits)

#define BTF_STRUCT_ENC(name, nr_elems, sz)      \
        BTF_TYPE_ENC(name, BTF_INFO_ENC(BTF_KIND_STRUCT, 1, nr_elems), sz)

#define BTF_MEMBER_ENC(name, type, bits_offset) \
        (name), (type), (bits_offset)

#define ICE_MD_SUPPORTED_HINTS_NUM_MMBRS 4
static const char names_str_supported[] = "\0xdp_supported_md\0hash\0flow_id\0vlan_id\0timestamp\0";

static const u32 ice_supported_md_raw[] = {
	BTF_TYPE_INT_ENC(0, 0, 0, 32, 4),
	BTF_TYPE_INT_ENC(0, 0, 0, 16, 2),
	BTF_STRUCT_ENC(1, ICE_MD_SUPPORTED_HINTS_NUM_MMBRS, 4 + 4 + 2 + 4),
		BTF_MEMBER_ENC(18, 1, 0), /* u32 hash */
		BTF_MEMBER_ENC(23, 1, 32), /* u32 flow_id */
		BTF_MEMBER_ENC(31, 2, 64), /* u16 vlan_id */
		BTF_MEMBER_ENC(39, 1, 80), /* u32 timestamp */
};

/* here is a mapping bettwen supported hints and used flex descriptor */
struct descriptor_mapping_info {
	const char *name;
	int offset;
	int size;
};

struct descriptor_mapping_info mapping_info[] = {
	[0] = { .name = "hash", .offset = 96, .size = 4},
	[1] = { .name = "flow_id", .offset = 192, .size = 4},
	[2] = { .name = "vlan_id", .offset = 224, .size = 2},
	[3] = { .name = "timestamp", .offset = 224, .size = 4}, /* overlap in descriptor */
};

struct descriptor_mapping {
	const struct descriptor_mapping_info *info;
	int amount;
} mapping = {
	.info = mapping_info,
	.amount = 4,
};

static struct btf *
ice_xdp_register_btf(void)
{
	int raw_size, str_size;
	struct btf_header *hdr;
	char *types, *names;
	struct btf *res;
	void *raw;
	int size;

	raw_size = sizeof(ice_supported_md_raw);
	str_size = sizeof(names_str_supported);
	size = sizeof(*hdr) + raw_size + str_size;
	raw = kzalloc(size, GFP_KERNEL);
	if (!raw)
		return NULL;

        hdr = raw;
        hdr->magic    = BTF_MAGIC;
        hdr->version  = BTF_VERSION;
        hdr->hdr_len  = sizeof(*hdr);
        hdr->type_off = 0;
        hdr->type_len = raw_size;
        hdr->str_off  = raw_size;
        hdr->str_len  = str_size;

	types = raw + sizeof(*hdr);
	names = types + raw_size;
	memcpy(types, ice_supported_md_raw, raw_size);
	memcpy(names, names_str_supported, str_size);

	res = btf_register(raw, size);

	kfree(raw);
	return res;
}

int ice_xdp_register_btfs(struct ice_netdev_priv *priv)
{
	int err = 0;

	priv->xdp.btf = ice_xdp_register_btf();
	if (IS_ERR(priv->xdp.btf)) {
		err = PTR_ERR(priv->xdp.btf);
		priv->xdp.btf = NULL;
	}

        return err;
}

void ice_xdp_unregister_btfs(struct ice_netdev_priv *priv)
{
	if (priv->xdp.btf)
		btf_unregister(priv->xdp.btf);
}

static int
ice_fill_mapping(struct btf *btf, const struct btf_member *member,
		 struct btf *supported_btf, struct ice_hints_mapping *mapping)
{
	int supported_id = btf_id_by_name(supported_btf, "xdp_supported_md");
	const struct btf_type *supported_type;
	const struct btf_type *program_type;
	const struct btf_member *mem;
	int i;

	program_type = btf_type_skip_modifiers(btf, member->type, NULL);

	if (supported_id < 0)
		return -1;

	supported_type = btf_type_by_id(supported_btf, supported_id);

	for_each_member(i, supported_type, mem) {
		struct ice_hints_mapping_info *info =
			&mapping->info[mapping->amount];
		const struct btf_type *driver_type;

		if (strcmp(btf_name_by_offset(btf, member->name_off),
			   btf_name_by_offset(supported_btf, mem->name_off)))
			continue;

		driver_type = btf_type_skip_modifiers(supported_btf, mem->type, NULL);

		if (program_type->size != driver_type->size)
			continue;

		info->offset = mapping_info[i].offset;
		info->size = mapping_info[i].size;
		info->mask = 0xff;

		mapping->amount += 1;
		mapping->size_in_bytes += program_type->size;

		return 0;
	}

	return -1;
}

int ice_hints_find(struct btf *btf, char *name, struct btf *supported_btf,
		   struct ice_hints_mapping *mapping)
{
	/* Search for name in btf */
	const struct btf_member *hints_member;
	int id = btf_id_by_name(btf, name);
	const struct btf_type *type;
	int size;
	int i;

	if (id < 0)
		return -1;

	type = btf_type_by_id(btf, id);
	size = btf_type_vlen(type);

	mapping->info = kcalloc(size, sizeof(struct ice_hints_mapping_info),
				GFP_KERNEL);
	mapping->amount = 0;
	mapping->size_in_bytes = 0;

	for_each_member(i, type, hints_member) {
		if (ice_fill_mapping(btf, hints_member, supported_btf,
				     mapping))
			return -1;
	}

	return 0;
}
