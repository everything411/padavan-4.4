ccflags-y=-Werror

obj-$(CONFIG_NET_MEDIATEK_HNAT)         += hw_nat.o
hw_nat-objs := hnat.o hnat_nf_hook.o hnat_debugfs.o hnat_mcast.o
hw_nat-$(CONFIG_NET_DSA_MT7530)	+= hnat_stag.o
