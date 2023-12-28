#include <linux/netdevice.h>

#define HNAT_PATH_ETHERNET      BIT(0)
#define HNAT_PATH_VLAN          BIT(1)
#define HNAT_PATH_PPPOE         BIT(2)
#define HNAT_PATH_DSA           BIT(3)
#define HNAT_PATH_DSLITE        BIT(4)
#define HNAT_PATH_6RD           BIT(5)
#define HNAT_PATH_TNL           BIT(6)

struct hnat_hw_path {
        const struct net_device *virt_dev;
        const struct net_device *real_dev;
        u32 flags;

        u8 eth_src[ETH_ALEN];
        u8 eth_dest[ETH_ALEN];
        u16 vlan_proto;
        u16 vlan_id;
        u16 pppoe_sid;
        u16 dsa_port;
};
