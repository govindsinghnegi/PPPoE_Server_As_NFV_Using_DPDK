static int do_dataplane_job(__attribute__((unused)) void *dummy) {

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
			if (DEBUG) {
				RTE_LOG(INFO, USER1, "=> Packet received... ethtype=%x\n", __bswap_16(l2hdr->ether_type));
			}

			//check if it is a PPPoE packet 
			if (__bswap_16(l2hdr->ether_type) == ETHER_DISCOVERY || __bswap_16(l2hdr->ether_type) == ETHER_SESSION) {
				
				PPPoEEncap * pppoee = (rte_pktmbuf_mtod(pkt, PPPoEEncap *));

				//check if it is a PADI packet
				if (pppoee->code == CODE_PADI) {
					
					if (DEBUG) {
						RTE_LOG(INFO, USER1, "=> Packet PADI received\n");
					}

					PPPoETag * pppoet;
					unsigned char serviceName[ETH_JUMBO_LEN]; //for keeping service name to be sent back in PADO
					unsigned char hostUnique[ETH_JUMBO_LEN]; //for keeping host unique to be sent back in PADO
					unsigned char relayId[ETH_JUMBO_LEN]; //relay id to be taken care, to be sent back in PADO
					uint16_t sn_length = 0, hu_length = 0, rd_length = 0;

					unsigned int seen = 0;
					unsigned int len = __bswap_16(pppoee->length);
					//parse PPPoE tags in the packet
					while (seen < len) {
						pppoet = rte_pktmbuf_mtod_offset(pkt, PPPoETag *, sizeof(PPPoEEncap)+seen);
						seen += sizeof(PPPoETag);
						//search for service name
						if (__bswap_16(pppoet->type) == TYPE_SERVICE_NAME) {
							//keep the default service name ready in case tag length is zero
							memcpy(serviceName, service_name, sizeof(service_name));
							sn_length = (uint16_t) sizeof(service_name);
							//check against all available service names (currenty only one exist)
							if (__bswap_16(pppoet->length) != 0) {
								sn_length = __bswap_16(pppoet->length);
								char * sr_value = rte_pktmbuf_mtod_offset(pkt, char *, sizeof(PPPoEEncap) + seen);
								memcpy(serviceName, sr_value, __bswap_16(pppoet->length));
								seen += __bswap_16(pppoet->length);
							}
						//search for host unique
						} else if (__bswap_16(pppoet->type) == TYPE_HOST_UNIQ) {
							hu_length = __bswap_16(pppoet->length);
							char * hu_value = rte_pktmbuf_mtod_offset(pkt, char *, sizeof(PPPoEEncap) + seen);
							memcpy(hostUnique, hu_value, __bswap_16(pppoet->length));
							seen += __bswap_16(pppoet->length);
						//search for relay session id
						} else if (__bswap_16(pppoet->type) == TYPE_RELAY_SESSION_ID) {
							rd_length = __bswap_16(pppoet->length);
                                        	        char * rd_value = rte_pktmbuf_mtod_offset(pkt, char *, sizeof(PPPoEEncap) + seen);
                                        	        memcpy(relayId, rd_value, __bswap_16(pppoet->length));
                                        	        seen += __bswap_16(pppoet->length);
						//search for max payload, not considered here
                                        	} else if (__bswap_16(pppoet->type) == 0x0120) {
                                        	} else {
							if (DEBUG) {
								RTE_LOG(INFO, USER1, "=> Unknown tag found in a PADI packet received\n");
							}
                                        	}
					}

					//check if asked service name matches our service name
					if (memcmp(serviceName, service_name, sizeof(service_name)) != 0) {
						if (DEBUG) {
							RTE_LOG(INFO, USER1, "=> Packet for unknown service name received, dropping...\n");
						}
						rte_pktmbuf_free(pkt);
						continue;
					}

					//generate a PADO packet to send back
					rte_pktmbuf_reset(pkt);
					PPPoEEncap * pppoeer = (PPPoEEncap *) rte_pktmbuf_append(pkt, sizeof(PPPoEEncap));
					memcpy(&pppoeer->l2hdr.d_addr, &pppoee->l2hdr.s_addr, sizeof(struct ether_addr));
					memcpy(&pppoeer->l2hdr.s_addr, &srtointra_addr, sizeof(struct ether_addr));
					pppoeer->l2hdr.ether_type = pppoee->l2hdr.ether_type;
					pppoeer->ver = pppoee->ver;
					pppoeer->type = pppoee->type;
					pppoeer->session = pppoee->session;
					pppoeer->code = CODE_PADO;
					pppoeer->length = 0;

					PPPoETag * pppoetr;
					unsigned int pppoe_payload_length = 0;
					//add AC_NAME tag
					pppoetr = (PPPoETag *) rte_pktmbuf_append(pkt, sizeof(PPPoETag));
					pppoetr->type = __bswap_16((uint16_t) (TYPE_AC_NAME));
					pppoetr->length = __bswap_16((uint16_t) (sizeof(ac_name)));
					char * ac_value = (char *) rte_pktmbuf_append(pkt, sizeof(ac_name));
					memcpy(ac_value, ac_name, sizeof(ac_name));
					pppoe_payload_length += sizeof(PPPoETag) + sizeof(ac_name);

					//add SERVICE_NAME tag
					pppoetr = (PPPoETag *) rte_pktmbuf_append(pkt, sizeof(PPPoETag));
                                	pppoetr->type = __bswap_16((uint16_t) (TYPE_SERVICE_NAME));
                                	pppoetr->length = __bswap_16((uint16_t) (sn_length));
                                	char * sr_value = (char *) rte_pktmbuf_append(pkt, sn_length);
					memcpy(sr_value, serviceName, sn_length);
					pppoe_payload_length += sizeof(PPPoETag) + sn_length;

					//add COOKIE tag
					pppoetr = (PPPoETag *) rte_pktmbuf_append(pkt, sizeof(PPPoETag));
                                	pppoetr->type = __bswap_16((uint16_t) (TYPE_AC_COOKIE));
					//replace the below code with a valid cookie generation code
                                	char * CKname = "CKNAME";
                                	pppoetr->length = __bswap_16((uint16_t) (sizeof(CKname)));
                                	char * ck_value = (char *) rte_pktmbuf_append(pkt, sizeof(CKname));
					memcpy(ck_value, CKname, sizeof(CKname));
					pppoe_payload_length += sizeof(PPPoETag) + sizeof(CKname);

					//add HOST_UNIQ tag if present in PADI
					if (hu_length != 0) {
                                		pppoetr = (PPPoETag *) rte_pktmbuf_append(pkt, sizeof(PPPoETag));
                                		pppoetr->type = __bswap_16((uint16_t) (TYPE_HOST_UNIQ));
                                		pppoetr->length = __bswap_16((uint16_t) (hu_length));
						char * hu_value = (char *) rte_pktmbuf_append(pkt, hu_length);
                                		memcpy(hu_value, hostUnique, hu_length);
						pppoe_payload_length += sizeof(PPPoETag) + hu_length;
					}

					//add RELAY_SESSION_ID tag if present in PADI
					if (rd_length != 0) {
                                		pppoetr = (PPPoETag *) rte_pktmbuf_append(pkt, sizeof(PPPoETag));
                                		pppoetr->type = __bswap_16((uint16_t) (TYPE_RELAY_SESSION_ID));
                                		pppoetr->length = __bswap_16((uint16_t) (rd_length));
						char * rd_value = (char *) rte_pktmbuf_append(pkt, rd_length);
                                		memcpy(rd_value, relayId, rd_length);
						pppoe_payload_length += sizeof(PPPoETag) + rd_length;
					}

					pppoeer->length = __bswap_16((uint16_t) (pppoe_payload_length));

				//check if it is a PADR packet
				} else if (pppoee->code == CODE_PADR) {

					if (DEBUG) {
						RTE_LOG(INFO, USER1, "=> Packet PADR received\n");
					}
                                //PPPoEEncap * pppoee;
                                	PPPoETag * pppoet;
                                	unsigned int readyToSend = 0; //must be set to 1 before sending a PADS, after verifying cookie
					unsigned char serviceName[ETH_JUMBO_LEN]; //for keeping service name to be sent back in PADS
					unsigned char hostUnique[ETH_JUMBO_LEN]; //for keeping host unique to be sent back in PADS
					unsigned char cookie[ETH_JUMBO_LEN]; //for temporarily keeping cookie, have to check agaist the generated one
					uint16_t sn_length, hu_length, ck_length;
                                	//pppoee = (rte_pktmbuf_mtod(pkt, PPPoEEncap *));
                                	//RTE_LOG(INFO, USER1, "=> Packet received...code = %u, legth = %u\n", pppoee->code, __bswap_16(pppoee->length));
					//if (pppoee->code == 0x19) {
					//	RTE_LOG(INFO, USER1, "=> Packet PADR received\n");
					//}

				//verify the cookie
				//check service name if present
				//check hostunique if present
				//for now just sending a hadcoded packet
				unsigned int seen = 0;
				unsigned int len = __bswap_16(pppoee->length);
				//parse PPPoE tags in the packet
				while (seen < len) {
					pppoet = rte_pktmbuf_mtod_offset(pkt, PPPoETag *, sizeof(PPPoEEncap)+seen);
					seen += sizeof(PPPoETag);
					//search for service name
					if (__bswap_16(pppoet->type) == TYPE_SERVICE_NAME) {
						//keep the default service name ready in case tag length is zero
						memcpy(serviceName, service_name, sizeof(service_name));
						sn_length = (uint16_t) sizeof(service_name);
						//check against all available service names (currenty only one exists)
						if (__bswap_16(pppoet->length) != 0) {
							sn_length = __bswap_16(pppoet->length);
							char * sr_value = rte_pktmbuf_mtod_offset(pkt, char *, sizeof(PPPoEEncap) + seen);
							memcpy(serviceName, sr_value, __bswap_16(pppoet->length));
							seen += __bswap_16(pppoet->length);
						}
					//search for host unique
					} else if (__bswap_16(pppoet->type) == TYPE_HOST_UNIQ) {
						hu_length = __bswap_16(pppoet->length);
						char * hu_value = rte_pktmbuf_mtod_offset(pkt, char *, sizeof(PPPoEEncap) + seen);
						memcpy(hostUnique, hu_value, __bswap_16(pppoet->length));
						seen += __bswap_16(pppoet->length);
					//search for cookie
					} else if (__bswap_16(pppoet->type) == TYPE_AC_COOKIE) {
						ck_length = __bswap_16(pppoet->length);
                                                char * ck_value = rte_pktmbuf_mtod_offset(pkt, char *, sizeof(PPPoEEncap) + seen);
                                                memcpy(cookie, ck_value, __bswap_16(pppoet->length));
                                                seen += __bswap_16(pppoet->length);
                                        } else if (__bswap_16(pppoet->type) == 0x0110) {
                                        } else if (__bswap_16(pppoet->type) == 0x0120) {
                                        } else {
                                        }
				}

				rte_pktmbuf_reset(pkt);
				uint16_t pkt_length = 0;
                                //RTE_LOG(INFO, USER1, "=> Packet received1...type = %u, legth = %u\n", __bswap_16(pppoet->type), __bswap_16(pppoet->length));
                                //RTE_LOG(INFO, USER1, "=> Packet size %u....%lu....%lu\n", pkt->data_len, sizeof(PPPoEEncap), sizeof(pkt));
                                PPPoEEncap * pppoeer = (PPPoEEncap *) rte_pktmbuf_append(pkt, sizeof(PPPoEEncap));
                                memcpy(&pppoeer->l2hdr.d_addr, &pppoee->l2hdr.s_addr, sizeof(struct ether_addr));
                                memcpy(&pppoeer->l2hdr.s_addr, &tasks_addr, sizeof(struct ether_addr));
                                pppoeer->l2hdr.ether_type = pppoee->l2hdr.ether_type;
                                pppoeer->ver = pppoee->ver;
                                pppoeer->type = pppoee->type;
				//TODO create a session here
                                pppoeer->session = (uint16_t) 1234;
                                pppoeer->code = 0x65;
                                pppoeer->length = 0;
                                //RTE_LOG(INFO, USER1, "=> short size %lu....int %lu\n",sizeof(unsigned short), sizeof(unsigned int));

                                PPPoETag * pppoetr = (PPPoETag *) rte_pktmbuf_append(pkt, sizeof(PPPoETag));
                                pppoetr->type = __bswap_16((uint16_t) (0x0101));
				pppoetr->length = __bswap_16(sn_length);
                                char * SNvalue = (char *) rte_pktmbuf_append(pkt, sn_length);
                                memcpy(SNvalue, serviceName, sn_length);
				pkt_length += sizeof(PPPoETag) + sn_length;

				pppoetr = (PPPoETag *) rte_pktmbuf_append(pkt, sizeof(PPPoETag));
                                pppoetr->type = __bswap_16((uint16_t) (0x0103));
                                pppoetr->length = __bswap_16(hu_length);
                                char * HUvalue = (char *) rte_pktmbuf_append(pkt, hu_length);
                                memcpy(HUvalue, hostUnique, hu_length);
				pkt_length += sizeof(PPPoETag) + hu_length;

				pppoeer->length = __bswap_16(pkt_length);

			} else if (memcmp(&tasks_addr, &l2hdr->d_addr, sizeof(struct ether_addr)) == 0 && pppoee->code == 0x00) {

				PPPoEEncap * pppoee;
                                PPPEncap * pppptcl;
				PPPLcp * ppplcp;
				PPPLcpOptionsGenl * ppplcpo;
				unsigned int seen = 0;
                                pppoee = rte_pktmbuf_mtod(pkt, PPPoEEncap *);
				pppptcl = rte_pktmbuf_mtod_offset(pkt, PPPEncap *, sizeof(PPPoEEncap)+seen);
				seen += sizeof(PPPEncap);
				if (__bswap_16(pppptcl->protocol) == 0xc021) {
					RTE_LOG(INFO, USER1, "=> Packet LCP received\n");
				} else if (__bswap_16(pppptcl->protocol) == 0xc023) {
					RTE_LOG(INFO, USER1, "=> Packet Authentication received\n");
					//need to do auth check here
				}
				ppplcp = rte_pktmbuf_mtod_offset(pkt, PPPLcp *, sizeof(PPPoEEncap)+seen);
				//ppplcp = rte_pktmbuf_mtod_offset(pkt, ppplcp *, sizeof(PPPoEEncap) + seen);
				seen += sizeof(PPPLcp);
				if (ppplcp->code == 1) {
					ppplcp->code = (uint8_t) 2;
				} else if (ppplcp->code == 9) {
					ppplcp->code = (uint8_t) 10;
					RTE_LOG(INFO, USER1, "Echo-request received\n");
				} else if (ppplcp->code == 10) {
					RTE_LOG(INFO, USER1, "Echo-request Ack received\n");
					rte_pktmbuf_free(pkt);
					continue;
				} else {
					RTE_LOG(INFO, USER1, "Configure-request ACK received\n");
					rte_pktmbuf_free(pkt);
					continue;
				}
                                memcpy(&pppoee->l2hdr.d_addr, &pppoee->l2hdr.s_addr, sizeof(struct ether_addr));
                                memcpy(&pppoee->l2hdr.s_addr, &tasks_addr, sizeof(struct ether_addr));

				if (__bswap_16(pppptcl->protocol) == 0xc021) {
					//consider sending the above packet first
					//then create a configure request from server for authentiation
					struct rte_mbuf * acpkt = rte_pktmbuf_alloc(mempool);
					PPPoEEncap * pppoeer = (PPPoEEncap *) rte_pktmbuf_append(acpkt, sizeof(PPPoEEncap));
                           		memcpy(&pppoeer->l2hdr.d_addr, &pppoee->l2hdr.d_addr, sizeof(struct ether_addr));
                                	memcpy(&pppoeer->l2hdr.s_addr, &tasks_addr, sizeof(struct ether_addr));
	                                pppoeer->l2hdr.ether_type = pppoee->l2hdr.ether_type;
        	                        pppoeer->ver = pppoee->ver;
                	                pppoeer->type = pppoee->type;
                        	        pppoeer->session = (uint16_t) 1234;
	                                pppoeer->code = 0x00;
        	                        pppoeer->length = 0;
                	                //RTE_LOG(INFO, USER1, "=> short size %lu....int %lu\n",sizeof(unsigned short), sizeof(unsigned int));

					uint16_t pppoe_payload_legth = 0;
					PPPEncap * pppptcls = (PPPEncap *) rte_pktmbuf_append(acpkt, sizeof(PPPEncap));
					pppptcls->protocol = __bswap_16(0xc021);
					pppoe_payload_legth += (uint16_t) sizeof(PPPEncap);

					PPPLcp * ppplcps = (PPPLcp *) rte_pktmbuf_append(acpkt, sizeof(PPPLcp));
					ppplcps->code = 0x01;
					ppplcps->identifier = 0x04;
					ppplcps->length = 0;
					uint16_t ppplcp_length = 0;
					pppoe_payload_legth += (uint16_t) sizeof(PPPLcp);
					ppplcp_length += (uint16_t) sizeof(PPPLcp);

					if (ppplcp->code == 9) {
						ppplcps->code = 0x09;
						ppplcps->length = 0x08;
						uint32_t * magic = (uint32_t *) rte_pktmbuf_append(acpkt, sizeof(uint32_t));
						*magic = 0x3241;
						pppoe_payload_legth += (uint16_t) 4;
						ppplcp_length += (uint16_t) 4;
						ppplcps->length = __bswap_16(ppplcp_length);
                                        	pppoeer->length = __bswap_16(pppoe_payload_legth);
						int retrn = rte_eth_tx_burst(ETHDEV_ID, 0, &acpkt, 1);
                                        	if (retrn != 1) {
                                              		RTE_LOG(INFO, USER1, "    TX burst failed with error code %i.\n", retrn);
                                        	}
						continue;
					}

					PPPLcpOptionsGenl * ppplcpos = (PPPLcpOptionsGenl *) rte_pktmbuf_append(acpkt, sizeof(PPPLcpOptionsGenl));
					ppplcpos->type = 0x03;
					ppplcpos->length = 0x04;
					ppplcpos->value = __bswap_16(0xc023);
					pppoe_payload_legth += (uint16_t) sizeof(PPPLcpOptionsGenl);
					ppplcp_length += (uint16_t) ppplcpos->length;

					PPPLcpOptionsEcho * magic = (PPPLcpOptionsEcho *) rte_pktmbuf_append(acpkt, sizeof(PPPLcpOptionsEcho));
					magic->type = 0x05;
                	                magic->length = 0x06;
                        	        magic->value = __bswap_16(0x12345678);
                                	pppoe_payload_legth += (uint16_t) sizeof(PPPLcpOptionsEcho);
					ppplcp_length += (uint16_t) magic->length;

					ppplcps->length = __bswap_16(ppplcp_length);
        	                        pppoeer->length = __bswap_16(pppoe_payload_legth);
					int retrn = rte_eth_tx_burst(ETHDEV_ID, 0, &acpkt, 1);
					if (retrn != 1) {
  	        	                      RTE_LOG(INFO, USER1, "    TX burst failed with error code %i.\n", retrn);
        	                	}
				}
				}

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












