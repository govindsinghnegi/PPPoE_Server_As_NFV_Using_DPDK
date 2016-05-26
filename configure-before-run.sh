lab_main.c                                                                                          0000664 0001750 0001750 00000014311 12721443417 012347  0                                                                                                    ustar   sooraj                          sooraj                                                                                                                                                                                                                 #include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <errno.h>

#include <sys/queue.h>
#include <sys/stat.h>

#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>

#include <rte_config.h>
#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_string_fns.h>
#include <rte_ip.h>
#include <rte_udp.h>


//======= Pre-Definitions

//#define TEST_HASH_ONLY

#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512
#define MAX_SIZE_BURST 32
#define MEMPOOL_CACHE_SIZE 256

//======= Definitions

#define CACHE_LINE_SIZE		64
#define UINT8_UNDEF		255
#define RTE_MAX_IFACE		255

#define MBUF_SIZE (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)

#define ETHDEV_ID	0

#include "lab_task.c"

static unsigned tz_getMBufMempoolSize(uint8_t ports_c, uint8_t lcores_c, uint8_t rx_queues_c, uint8_t tx_queues_c) {

	unsigned result =
	ports_c * rx_queues_c * RTE_TEST_RX_DESC_DEFAULT + 
	ports_c * lcores_c * MAX_SIZE_BURST + 
	ports_c * tx_queues_c * RTE_TEST_TX_DESC_DEFAULT + 
	lcores_c * MEMPOOL_CACHE_SIZE;

	if (result < 8192) return 8192;
	return result;

}

int ethaddr_to_string(char* str2write, const struct ether_addr* eth_addr) {

	return sprintf (str2write, "%02x:%02x:%02x:%02x:%02x:%02x",
		eth_addr->addr_bytes[0],
		eth_addr->addr_bytes[1],
		eth_addr->addr_bytes[2],
		eth_addr->addr_bytes[3],
		eth_addr->addr_bytes[4],
		eth_addr->addr_bytes[5]);
}

int main(int argc, char **argv) {

	static struct rte_eth_conf default_ethconf = {
		.link_speed = 0,
		.link_duplex = 0,
		.rxmode = {
			.mq_mode = ETH_MQ_RX_NONE,
			.max_rx_pkt_len = 0,
			.split_hdr_size = 0,
			.header_split = 0,
			.hw_ip_checksum = 0,
			.hw_vlan_filter = 0,
			.hw_vlan_strip = 0,
			.hw_vlan_extend = 0,
			.jumbo_frame = 0,
			.hw_strip_crc = 0,
			.enable_scatter = 0,
			.enable_lro = 0,
		},
		.txmode = {
			.mq_mode = ETH_MQ_TX_NONE,
			.hw_vlan_reject_tagged = 0,
			.hw_vlan_reject_untagged = 0,
			.hw_vlan_insert_pvid = 0,
		},
		.lpbk_mode = 0,
		.rx_adv_conf = {
			.rss_conf = {		//Receive Side Scaling.
				.rss_key = NULL,
				.rss_key_len = 0,
				.rss_hf = 0,
			},
		},
	};
		
	static const struct rte_eth_rxconf rx_conf = {
		.rx_thresh = {
			.pthresh = 8,	//prefetch
			.hthresh = 8,	//host
			.wthresh = 4	//write-back
		},
		.rx_free_thresh = 32,
	};	

	static struct rte_eth_txconf tx_conf = {
		.tx_thresh = {
			.pthresh = 36,
			.hthresh = 0,
			.wthresh = 0
		},
		.tx_free_thresh = 0,
		.tx_rs_thresh = 0,
		.txq_flags = (ETH_TXQ_FLAGS_NOMULTSEGS |
			ETH_TXQ_FLAGS_NOVLANOFFL |
			ETH_TXQ_FLAGS_NOXSUMSCTP |
			ETH_TXQ_FLAGS_NOXSUMUDP |
			ETH_TXQ_FLAGS_NOXSUMTCP)

	};

	int status;

	printf("[[I]] Starting DPDK EAL...\n");
	
	status = rte_eal_init(argc, argv);
	if (status < 0) {
		rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
	}

	printf("[[I]] Checking for ports...\n");

	uint8_t devcount = rte_eth_dev_count();

	if (devcount == 0) {
		rte_exit(EXIT_FAILURE, "No probed ethernet devices\n");
		printf("[[I]] No devs, exiting\n");
	}
	printf("[[I]] Found %i net devices.\n", devcount);

	
	uint8_t i;
	uint8_t our_lcore = 255;

	for (i=0; i < RTE_MAX_LCORE; i++) {
		
		if (rte_lcore_is_enabled(i) && !(rte_get_master_lcore() == i)) {
			//printf("  Adding.\n");
			our_lcore = i;
			break;
		}
	}

	if (our_lcore == 255) {
		rte_exit(EXIT_FAILURE, "No lcores were available\n");
	}

	argc -= status;
	argv += status;

	//Find the interior and exterior interface by MAC address...
	printf("[[I]] Associating devices...\n");

	//Claims the first available interface for DPDK.
	struct ether_addr found_dev_macaddr;
	rte_eth_macaddr_get(ETHDEV_ID, &found_dev_macaddr);
	char ether_addr_string[20]; 
	ethaddr_to_string(ether_addr_string, &found_dev_macaddr);	//TODO
	printf("  MAC Address of device: %s\n", ether_addr_string);

	status = rte_eth_dev_configure(ETHDEV_ID, 1, 1, &default_ethconf);
	if (status < 0) {
		rte_exit(EXIT_FAILURE, "Could not configure ethernet device %i.\n", i);
	}

	uint8_t socket = rte_lcore_to_socket_id(our_lcore);
		//We are on this socket, necessary for NUMA

	//Set up a mempool for packets

	printf("[[I]] Configuring mempool...\n");
	unsigned mempool_sz = tz_getMBufMempoolSize(1,1,1,1);	//TODO
	struct rte_mempool* mempool = rte_mempool_create("DEFAULT_MEMPOOL",
		mempool_sz, //The number of elements in the mempool. n = (2^q - 1).
		MBUF_SIZE,	//Size of each element
		MEMPOOL_CACHE_SIZE,
		sizeof(struct rte_pktmbuf_pool_private),
		rte_pktmbuf_pool_init, NULL,
		rte_pktmbuf_init, NULL, socket, 0);

	if (mempool == NULL)
		rte_exit(EXIT_FAILURE, "MBuf creation failed for interface %i\n", i);

	printf("[[I]] Preparing queues...\n");

	status = rte_eth_rx_queue_setup(ETHDEV_ID, 
		0, 
		RTE_TEST_RX_DESC_DEFAULT,
		socket,
		&rx_conf,
		mempool);

	if (status < 0) rte_exit(EXIT_FAILURE, "Failed to set up TX queue\n");

	status = rte_eth_tx_queue_setup(ETHDEV_ID, 
		0, 
		RTE_TEST_TX_DESC_DEFAULT,
		socket,
		&tx_conf);

	if (status < 0) rte_exit(EXIT_FAILURE, "Failed to set up RX queue\n");

	status = rte_eth_dev_start(ETHDEV_ID);
	if (status < 0) rte_exit(EXIT_FAILURE, "Failed to fire up interface\n");

	rte_eth_promiscuous_enable(ETHDEV_ID);

	//Wait for ports up
	printf("[[I]] Waiting for ports up...\n");

	struct rte_eth_link link;
	int up = 0;
	while (1) {
		memset(&link, 0, sizeof(link));
		rte_eth_link_get_nowait(ETHDEV_ID, &link);
		printf("  Link ");
		if (link.link_status) {
			printf("up\n");
			up = 1;
			break;
		} else {
			printf("down\n");
		}
		rte_delay_ms(200);
	}

	printf("[[I]] Launching data plane cores...\n");
	rte_eal_remote_launch(do_dataplane_job, NULL, our_lcore);
	if (rte_eal_wait_lcore(our_lcore) < 0)
			return -1;


	printf("[[I]] Exiting.\n");


	return 0;

}





                                                                                                                                                                                                                                                                                                                       lab_task.c                                                                                          0000664 0001750 0001750 00000017251 12721443417 012373  0                                                                                                    ustar   sooraj                          sooraj                                                                                                                                                                                                                 #define BURSTLEN	4
#define ETH_JUMBO_LEN	(16)
#define PPPOE_OVERHEAD 	6
#define HDR_SIZE	(sizeof(struct ether_hdr) + PPPOE_OVERHEAD)
#define PPP_OVERHEAD	4

static int do_dataplane_job(__attribute__((unused)) void *dummy) {

	typedef unsigned short unit16_t;

	/* PPPoE packet structure */

	typedef struct __attribute__((__packed__)) {
		struct ether_hdr l2hdr;
		unsigned int type:4;
		unsigned int ver:4;
		unsigned int code:8;
		unsigned int session:16;
		unsigned int length:16;
		//unsigned char payload[ETH_JUMBO_LEN];
	} PPPoEEncap;

	/* PPPoE tag Structure*/

	typedef struct __attribute__((__packed__)) {
		unsigned int type:16;
		unsigned int length:16;
		//unsigned char payload[ETH_JUMBO_LEN];
	} PPPoETag;

	unsigned char tag_hostunique[ETH_JUMBO_LEN];
	unit16_t hostunique_size;

	uint8_t lcore_id = rte_lcore_id();

	struct rte_mbuf* rcv_pkt_bucket[BURSTLEN];

	while(1) {

		uint32_t rx_pkt_count = rte_eth_rx_burst(ETHDEV_ID, 0, rcv_pkt_bucket, BURSTLEN);
		int i;

		for (i=0; i < rx_pkt_count; i++) {
			struct rte_mbuf* pkt = rcv_pkt_bucket[i];

			rte_prefetch0(rte_pktmbuf_mtod(pkt, void*));
			struct ether_hdr* l2hdr;
			l2hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr*);
			RTE_LOG(INFO, USER1, "=> Packet received... ethtype=%u\n", __bswap_16(l2hdr->ether_type));

			//=== BEGIN Your code

			//Demo:
			//const struct ether_addr addr2set = {.addr_bytes={0x52,0x00,0x01,0x02,0x03,0x04}};	//52:00:01:02:03:04
			//memcpy(&l2hdr->s_addr, &addr2set, sizeof(struct ether_addr));

			const struct ether_addr taskr_addr = {.addr_bytes={0xff,0xff,0xff,0xff,0xff,0xff}};
			const struct ether_addr tasks_addr = {.addr_bytes={0x08,0x00,0x27,0xa5,0xe0,0x94}};
			const struct ether_addr task2_addr = {.addr_bytes={0x0a,0x00,0x27,0x00,0x00,0x00}};
			const struct ether_addr task3_addr = {.addr_bytes={0x00,0x15,0x17,0x03,0x00,0x03}};

			if (memcmp(&taskr_addr, &l2hdr->d_addr, sizeof(struct ether_addr)) == 0) {
				RTE_LOG(INFO, USER1, "=> Packet received... bradcast\n");
				PPPoEEncap * pppoee;
				PPPoETag * pppoet;
				static char * test;
				pppoee = (rte_pktmbuf_mtod(pkt, PPPoEEncap *));
				RTE_LOG(INFO, USER1, "=> Packet received...code = %u, legth = %u\n", pppoee->code, __bswap_16(pppoee->length));
				pppoet = rte_pktmbuf_mtod_offset(pkt, PPPoETag *, sizeof(PPPoEEncap));
				//unsigned int* p = (rte_pktmbuf_mtod(pkt, unsigned int *));
				//RTE_LOG(INFO, USER1, "=> Packet received...type = %u\n", __bswap_32(*p));
				//struct rte_mbuf* tpkt = (struct rte_mbuf*) rte_pktmbuf_adj(pkt, PPPOE_OVERHEAD);
				//pppoet = (rte_pktmbuf_mtod(test, PPPoETag *));
				RTE_LOG(INFO, USER1, "=> Packet received1...type = %u, legth = %u\n", __bswap_16(pppoet->type), __bswap_16(pppoet->length));
				pppoet = rte_pktmbuf_mtod_offset(pkt, PPPoETag *, sizeof(PPPoEEncap) + sizeof(PPPoETag));
				RTE_LOG(INFO, USER1, "=> Packet received2...type = %u, legth = %u\n", __bswap_16(pppoet->type), __bswap_16(pppoet->length));
				//unsigned int p = (unsigned int) __bswap_16(pppoet->length);
				if((__bswap_16(pppoet->length))!=0) {
					char * k = rte_pktmbuf_mtod_offset(pkt, char *, sizeof(PPPoEEncap) + 2 * sizeof(PPPoETag));
					memcpy(tag_hostunique, k, __bswap_16(pppoet->length));
					hostunique_size = __bswap_16(pppoet->length);
					char * kk = (char *)(pppoee + sizeof(PPPoEEncap) + 2 * sizeof(PPPoETag));
					RTE_LOG(INFO, USER1, "=> Packet received2...value = %x%x%x%x....%u\n", tag_hostunique[0], tag_hostunique[1], tag_hostunique[2], tag_hostunique[3], hostunique_size);
				}
				//struct rte_mbuf* rpkt;
				//rte_pktmbuf_trim(pkt, (2 * sizeof(PPPoETag) + (__bswap_16(pppoet->length))));
				//rte_pktmbuf_trim(pkt, __bswap_16(pppoee->length));
				//PPPoETag * q = (PPPoETag *) rte_pktmbuf_append(pkt, 8);
				//q->type = __bswap_16(pppoet->type); q->length = __bswap_16(pppoet->length);
				//pppoee = (rte_pktmbuf_mtod(pkt, PPPoEEncap *));
				//pppoet = rte_pktmbuf_mtod_offset(pkt, PPPoETag *, sizeof(PPPoEEncap));
                                //unsigned int* p = (rte_pktmbuf_mtod(pkt, unsigned int *));
                                //RTE_LOG(INFO, USER1, "=> Packet received...type = %u\n", __bswap_32(*p));
                                //struct rte_mbuf* tpkt = (struct rte_mbuf*) rte_pktmbuf_adj(pkt, PPPOE_OVERHEAD);
                                //pppoet = (rte_pktmbuf_mtod(test, PPPoETag *));
				rte_pktmbuf_reset(pkt);
                                RTE_LOG(INFO, USER1, "=> Packet received1...type = %u, legth = %u\n", __bswap_16(pppoet->type), __bswap_16(pppoet->length));
				RTE_LOG(INFO, USER1, "=> Packet size %u....%lu....%lu\n", pkt->data_len, sizeof(PPPoEEncap), sizeof(pkt));
				PPPoEEncap * pppoeer = (PPPoEEncap *) rte_pktmbuf_append(pkt, sizeof(PPPoEEncap));
				memcpy(&pppoeer->l2hdr.d_addr, &pppoee->l2hdr.s_addr, sizeof(struct ether_addr));
				memcpy(&pppoeer->l2hdr.s_addr, &tasks_addr, sizeof(struct ether_addr));
				pppoeer->l2hdr.ether_type = pppoee->l2hdr.ether_type;
				pppoeer->ver = pppoee->ver;
				pppoeer->type = pppoee->type;
				pppoeer->session = pppoee->session;
				pppoeer->code = 0x07;
				pppoeer->length = 0;
				RTE_LOG(INFO, USER1, "=> Packet size %u....%lu....%lu\n", pkt->data_len, sizeof(PPPoEEncap), sizeof(pkt));
				//RTE_LOG(INFO, USER1, "=> short size %lu....int %lu\n",sizeof(unsigned short), sizeof(unsigned int));
				PPPoETag * pppoetr = (PPPoETag *) rte_pktmbuf_append(pkt, sizeof(PPPoETag));
				pppoetr->type = __bswap_16((unit16_t) (0x0102));
				char * ACname = "ACNAME";
				pppoetr->length = __bswap_16((unit16_t) (sizeof(ACname)));
				char * ac_value = (char *) rte_pktmbuf_append(pkt, sizeof(ACname));
				memcpy(ac_value, ACname, sizeof(ACname));

				pppoetr = (PPPoETag *) rte_pktmbuf_append(pkt, sizeof(PPPoETag));
                                pppoetr->type = __bswap_16((unit16_t) (0x0101));
                                char * SRname = "SRNAME";
                                pppoetr->length = __bswap_16((unit16_t) (sizeof(SRname)));
                                char * sr_value = (char *) rte_pktmbuf_append(pkt, sizeof(SRname));
				memcpy(sr_value, SRname, sizeof(SRname));

				pppoetr = (PPPoETag *) rte_pktmbuf_append(pkt, sizeof(PPPoETag));
                                pppoetr->type = __bswap_16((unit16_t) (0x0104));
                                char * CKname = "CKNAME";
                                pppoetr->length = __bswap_16((unit16_t) (sizeof(CKname)));
                                char * ck_value = (char *) rte_pktmbuf_append(pkt, sizeof(CKname));
				memcpy(ck_value, CKname, sizeof(CKname));

                                pppoetr = (PPPoETag *) rte_pktmbuf_append(pkt, sizeof(PPPoETag));
                                pppoetr->type = __bswap_16((unit16_t) (0x0103));
                                pppoetr->length = __bswap_16(hostunique_size);
				char * hu_value = (char *) rte_pktmbuf_append(pkt, hostunique_size);
                                memcpy(hu_value, tag_hostunique, hostunique_size);

				pppoeer->length = __bswap_16((unit16_t) (4*sizeof(PPPoETag)+sizeof(ACname)+sizeof(SRname)+sizeof(CKname))+hostunique_size);
				//pppoeer->length = (unit16_t) (
			} else if (memcmp(&tasks_addr, &l2hdr->d_addr, sizeof(struct ether_addr)) == 0) {
				RTE_LOG(INFO, USER1, "=> Packet PADR received\n");

			} else if (memcmp(&task3_addr, &l2hdr->d_addr, sizeof(struct ether_addr)) == 0) {
				//Task 3

			} else {
				RTE_LOG(INFO, USER1, "=> Packet for unknown target received, dropping...\n");
				rte_pktmbuf_free(pkt);
				continue;
			}

			//=== END Your code

			int retrn = rte_eth_tx_burst(ETHDEV_ID, 0, &rcv_pkt_bucket[i], 1);
				//For better performance, you could also bulk-send multiple packets here.
			if (retrn != 1) {
				RTE_LOG(INFO, USER1, "    TX burst failed with error code %i.\n", retrn);
			}

		}

	}

	return 0;


}












                                                                                                                                                                                                                                                                                                                                                       Makefile                                                                                            0000664 0001750 0001750 00000001001 12721443417 012071  0                                                                                                    ustar   sooraj                          sooraj                                                                                                                                                                                                                 CC=gcc

# Should contain pre-built DPDK at least.
RTE_SDK=deps/dpdk

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

LDDIRS += -L$(RTE_SDK)/$(RTE_TARGET)/lib	#Here, libdpdk.so should reside.

LDLIBS += -ldpdk
LDLIBS += -ldl
LDLIBS += -lpthread
#LDLIBS += -lxml2 
LDLIBS += -lm

app: lab_main.o
	$(CC) $(LDDIRS) -o lab_main lab_main.o $(LDLIBS)

lab_main.o: lab_main.c lab_task.c
	$(CC) -mssse3 -I../grt -I$(RTE_SDK)/$(RTE_TARGET)/include -c lab_main.c

                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               run.sh                                                                                              0000755 0001750 0001750 00000000743 12721443417 011606  0                                                                                                    ustar   sooraj                          sooraj                                                                                                                                                                                                                 #!/bin/bash

DPDK_DIR=deps/dpdk
DPDK_PLAF=x86_64-native-linuxapp-gcc

#Required kernel modules
modprobe uio
insmod $DPDK_DIR/$DPDK_PLAF/kmod/igb_uio.ko
insmod $DPDK_DIR/$DPDK_PLAF/kmod/rte_kni.ko

#The following must be done for every device we want to use. Only for VirtIO devices this is not required.
$DPDK_DIR/tools/dpdk_nic_bind.py --bind igb_uio 0000:00:08.0

export LD_LIBRARY_PATH=$DPDK_DIR/$DPDK_PLAF/lib
./lab_main -c3 -n4 -d $DPDK_DIR/$DPDK_PLAF/lib/librte_pmd_virtio.so

                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             