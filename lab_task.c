#define BURSTLEN	4
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












