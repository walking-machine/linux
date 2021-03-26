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

#define ICE_MD_FLEX_NUM_MMBRS 16
static const char names_str_flex[] = "\0xdp_md_desc\0rxdid\0mir_id_umb_cast\0ptype\0pkt_len\0hdr_len\0status_err0\0l2tag1\0rss_hash\0status_err1\0flex_flags2\0ts_low\0l2tag2_1st\0l2tag2_2nd\0flow_id\0vlan_id\0flow_id_ipv6\0";
#define ICE_MD_GENERIC_NUM_MMBRS 2
static const char names_str_generic[] = "\0xdp_md_gene\0hash\0flow_id\0";

static const u32 ice_md_raw_types_flex[] = {
        BTF_TYPE_INT_ENC(0, 0, 0, 32, 4),         /* type [1] */
	BTF_TYPE_INT_ENC(0, 0, 0, 16, 2),         /* type [2] */
	BTF_TYPE_INT_ENC(0, 0, 0, 8, 1),         /* type [3] */
        BTF_STRUCT_ENC(1, ICE_MD_FLEX_NUM_MMBRS, 1 + 1 + 2 + 2 + 2 + 2 + 2 + 4 + 2 +
		       1 + 1 + 2 + 2 + 4 + 2 + 2),
                BTF_MEMBER_ENC(13, 3, 0),   /* u8 rxdid;    */
                BTF_MEMBER_ENC(19, 3, 8),  /* u8 mir_id_umb_cast;       */
		BTF_MEMBER_ENC(35, 2, 16),  /* u16 ptype;         */
		BTF_MEMBER_ENC(41, 2, 32), /* u16 pkt_len; */
		BTF_MEMBER_ENC(49, 2, 48), /* u16 hdr_len; */
		BTF_MEMBER_ENC(57, 2, 64), /* u16 status_err0; */
		BTF_MEMBER_ENC(69, 2, 80), /* u16 l2tag1; */
		BTF_MEMBER_ENC(76, 1, 96), /* u32 rss_hash */
		BTF_MEMBER_ENC(85, 2, 128), /* u16 status_err1; */
		BTF_MEMBER_ENC(97, 3, 144), /* u8 flex_flags2; */
		BTF_MEMBER_ENC(109, 3, 152), /* u8 ts_low */
		BTF_MEMBER_ENC(116, 2, 160), /* u16 l2tag2_1st; */
		BTF_MEMBER_ENC(127, 2, 176), /* u16 l2tag2_2nd; */
		BTF_MEMBER_ENC(138, 1, 192), /* u32 flow_id; */
		BTF_MEMBER_ENC(146, 2, 224), /* u16 vlan_id; */
		BTF_MEMBER_ENC(154, 2, 240), /* u16 flow_id_ipv6; */
};

static const u32 ice_md_raw_types_generic[] = {
	BTF_TYPE_INT_ENC(0, 0, 0, 32, 4),
	BTF_TYPE_INT_ENC(0, 0, 0, 16, 2),
	BTF_STRUCT_ENC(1, ICE_MD_GENERIC_NUM_MMBRS, 4 + 4),
		BTF_MEMBER_ENC(13, 1, 0), /* u32 hash */
		BTF_MEMBER_ENC(18, 1, 32), /* u16 flow_id */
};

struct btf_info {
	int types_sz;
	int names_sz;
	const char *names;
	const u32 *types;
} ice_btfs_info[] = {
	{
		.types_sz = sizeof(ice_md_raw_types_flex),
		.names_sz = sizeof(names_str_flex),
		.names = names_str_flex,
		.types = ice_md_raw_types_flex,
	},
	{
		.types_sz = sizeof(ice_md_raw_types_generic),
		.names_sz = sizeof(names_str_generic),
		.names = names_str_generic,
		.types = ice_md_raw_types_generic,
	},
};

static struct btf *
ice_xdp_register_btf(struct btf_info *info)
{
	struct btf_header *hdr;
	char *types, *names;
	struct btf *res;
	void *raw;
	int size;

	size = sizeof(*hdr) + info->types_sz + info->names_sz;
	raw = kzalloc(size, GFP_KERNEL);
	if (!raw)
		return NULL;

        hdr = raw;
        hdr->magic    = BTF_MAGIC;
        hdr->version  = BTF_VERSION;
        hdr->hdr_len  = sizeof(*hdr);
        hdr->type_off = 0;
        hdr->type_len = info->types_sz;
        hdr->str_off  = info->types_sz;
        hdr->str_len  = info->names_sz;

	types = raw + sizeof(*hdr);
	names = types + info->types_sz;
	memcpy(types, info->types, info->types_sz);
	memcpy(names, info->names, info->names_sz);

	res = btf_register(raw, size);

	kfree(raw);
	return res;
}

int
ice_xdp_register_btfs(struct ice_netdev_priv *priv)
{
	int btfs_amount = ARRAY_SIZE(ice_btfs_info);
	int err = 0;
	int i;

	priv->xdp.btfs = kzalloc(btfs_amount * sizeof(struct btf *), GFP_KERNEL);
	if (!priv->xdp.btfs)
		return -ENOMEM;

	for (i = 0; i < btfs_amount; i++) {
		priv->xdp.btfs[i] = ice_xdp_register_btf(&ice_btfs_info[i]);
		if (IS_ERR(priv->xdp.btfs[i])) {
			err = PTR_ERR(priv->xdp.btfs[i]);
			priv->xdp.btfs[i] = NULL;
		}
	}

        return err;
}

void
ice_xdp_unregister_btfs(struct ice_netdev_priv *priv)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ice_btfs_info); i++) {
		if (priv->xdp.btfs[i])
			btf_unregister(priv->xdp.btfs[i]);
	}

	kfree(priv->xdp.btfs);
}
