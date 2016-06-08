
static int do_dataplane_job(__attribute__((unused)) void *dummy) {

	uint8_t lcore_id = rte_lcore_id();

	struct rte_mbuf* rcv_pkt_bucket[BURSTLEN];

	/*
	 *main loop for packet processing
	 */
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
                                        	} else {
							if (DEBUG) {
								RTE_LOG(INFO, USER1, "=> Unknown tag found in a PADI packet received\n");
							}
                                        	}
					}

					//check if asked service name matches our service name
					if (sn_length != 0 && memcmp(serviceName, service_name, sizeof(service_name)) != 0) {
						if (DEBUG) {
							RTE_LOG(INFO, USER1, "=> PADI packet for unknown service name received, dropping...\n");
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

					//send the packet
					int retrn = rte_eth_tx_burst(ETHDEV_ID, 0, &rcv_pkt_bucket[i], 1);
					if (retrn != 1 && DEBUG) {
						RTE_LOG(INFO, USER1, "TX burst failed with error code %i.\n", retrn);
					}
					continue;

				//check if it is a PADR packet
				} else if (pppoee->code == CODE_PADR) {

					if (DEBUG) {
						RTE_LOG(INFO, USER1, "=> Packet PADR received\n");
					}

                                	PPPoETag * pppoet;
					unsigned char serviceName[ETH_JUMBO_LEN]; //for keeping service name to be sent back in PADS
					unsigned char hostUnique[ETH_JUMBO_LEN]; //for keeping host unique to be sent back in PADS
					unsigned char cookie[ETH_JUMBO_LEN]; //for temporarily keeping cookie, have to check agaist the generated one
					unsigned char relayId[ETH_JUMBO_LEN]; //relay id to be taken care, to be sent back in PADS
					uint16_t sn_length = 0, hu_length = 0, ck_length = 0, rd_length = 0;

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
						//search for relay session id
						} else if (__bswap_16(pppoet->type) == TYPE_RELAY_SESSION_ID) {
							rd_length = __bswap_16(pppoet->length);
                                        	        char * rd_value = rte_pktmbuf_mtod_offset(pkt, char *, sizeof(PPPoEEncap) + seen);
                                        	        memcpy(relayId, rd_value, __bswap_16(pppoet->length));
                                        	        seen += __bswap_16(pppoet->length);
                                        	} else {
							if (DEBUG) {
								RTE_LOG(INFO, USER1, "=> Unknown tag found in a PADS packet received\n");
							}
							rte_pktmbuf_free(pkt);
							continue;
                                        	}
					}

					//verify the cookie received 
	
					//check if asked service name matches our service name
					if (sn_length != 0 && memcmp(serviceName, service_name, sizeof(service_name)) != 0) {
						if (DEBUG) {
							RTE_LOG(INFO, USER1, "=> PADR packet for unknown service name received, dropping...\n");
						}
						rte_pktmbuf_free(pkt);
						continue;
					}


					//create a session


					//generate a PADS packet to send back
					rte_pktmbuf_reset(pkt);
					PPPoEEncap * pppoeer = (PPPoEEncap *) rte_pktmbuf_append(pkt, sizeof(PPPoEEncap));
					memcpy(&pppoeer->l2hdr.d_addr, &pppoee->l2hdr.s_addr, sizeof(struct ether_addr));
					memcpy(&pppoeer->l2hdr.s_addr, &srtointra_addr, sizeof(struct ether_addr));
					pppoeer->l2hdr.ether_type = pppoee->l2hdr.ether_type;
					pppoeer->ver = pppoee->ver;
                                	pppoeer->type = pppoee->type;
					//TODO a random session for now
                                	pppoeer->session = __bswap_16((uint16_t) 1234);
                                	pppoeer->code = CODE_PADS;
                                	pppoeer->length = 0;

					PPPoETag * pppoetr;
					unsigned int pppoe_payload_length = 0;
					//add SERVICE_NAME tag
					pppoetr = (PPPoETag *) rte_pktmbuf_append(pkt, sizeof(PPPoETag));
                                	pppoetr->type = __bswap_16((uint16_t) (TYPE_SERVICE_NAME));
                                	pppoetr->length = __bswap_16((uint16_t) (sn_length));
                                	char * sr_value = (char *) rte_pktmbuf_append(pkt, sn_length);
					memcpy(sr_value, serviceName, sn_length);
					pppoe_payload_length += sizeof(PPPoETag) + sn_length;

					//add HOST_UNIQ tag if present in PADR
					if (hu_length != 0) {
                                		pppoetr = (PPPoETag *) rte_pktmbuf_append(pkt, sizeof(PPPoETag));
                                		pppoetr->type = __bswap_16((uint16_t) (TYPE_HOST_UNIQ));
                                		pppoetr->length = __bswap_16((uint16_t) (hu_length));
						char * hu_value = (char *) rte_pktmbuf_append(pkt, hu_length);
                                		memcpy(hu_value, hostUnique, hu_length);
						pppoe_payload_length += sizeof(PPPoETag) + hu_length;
					}

					//add RELAY_SESSION_ID tag if present in PADR
					if (rd_length != 0) {
                                		pppoetr = (PPPoETag *) rte_pktmbuf_append(pkt, sizeof(PPPoETag));
                                		pppoetr->type = __bswap_16((uint16_t) (TYPE_RELAY_SESSION_ID));
                                		pppoetr->length = __bswap_16((uint16_t) (rd_length));
						char * rd_value = (char *) rte_pktmbuf_append(pkt, rd_length);
                                		memcpy(rd_value, relayId, rd_length);
						pppoe_payload_length += sizeof(PPPoETag) + rd_length;
					}

					pppoeer->length = __bswap_16((uint16_t) (pppoe_payload_length));

					//send the packet to peer
					int retrn = rte_eth_tx_burst(ETHDEV_ID, 0, &rcv_pkt_bucket[i], 1);
					if (retrn != 1 && DEBUG) {
						RTE_LOG(INFO, USER1, "TX burst failed with error code %i.\n", retrn);
					}

					//send a Configure-request for Authetication to peer
					send_config_req((uint8_t)TYPE_AUP, (uint16_t)1234, pppoee->l2hdr.d_addr);
					continue;

				//check if it is a session packet
				} else if (pppoee->code == CODE_SESS) {

					if (DEBUG) {
						RTE_LOG(INFO, USER1, "=> Session Packet received\n");
					}

                                	PPPEncap * pppptcl;
					unsigned int seen = 0;
					pppptcl = rte_pktmbuf_mtod_offset(pkt, PPPEncap *, sizeof(PPPoEEncap)+seen);
					seen += sizeof(PPPEncap);

					//check if it is a LCP packet
					if (__bswap_16(pppptcl->protocol) == PROTO_LCP) {
						if (DEBUG) {
							RTE_LOG(INFO, USER1, "=> LCP Packet received\n");
						}

						PPPLcp * ppplcp;
						ppplcp = rte_pktmbuf_mtod_offset(pkt, PPPLcp *, sizeof(PPPoEEncap)+seen);
						seen += sizeof(PPPLcp);
						if (ppplcp->code == CODE_CONF_REQ) {
							if (DEBUG) {
								RTE_LOG(INFO, USER1, "=> Configure-request Packet received\n");
							}

							//check the configuration parameter, for now just send a ACK

							ppplcp->code = CODE_CONF_ACK;
                                			memcpy(&pppoee->l2hdr.d_addr, &pppoee->l2hdr.s_addr, sizeof(struct ether_addr));
                                			memcpy(&pppoee->l2hdr.s_addr, &srtointra_addr, sizeof(struct ether_addr));
							//send the Configure-reply packet to peer
							int retrn = rte_eth_tx_burst(ETHDEV_ID, 0, &rcv_pkt_bucket[i], 1);
							if (retrn != 1 && DEBUG) {
								RTE_LOG(INFO, USER1, "TX burst failed with error code %i.\n", retrn);
							}
							continue;

						} else if (ppplcp->code == CODE_ECHO_REQ) {
							if (DEBUG) {
								RTE_LOG(INFO, USER1, "=> Echo-request Packet received\n");
							}

							//check the configuration parameter, for now just send a Echo-request

							ppplcp->code = CODE_ECHO_REP;

							//send an echo-request back
							send_echo_req((uint16_t)1234, pppoee->l2hdr.s_addr);

							memcpy(&pppoee->l2hdr.d_addr, &pppoee->l2hdr.s_addr, sizeof(struct ether_addr));
                                			memcpy(&pppoee->l2hdr.s_addr, &srtointra_addr, sizeof(struct ether_addr));
							//send the Echo-reply packet to peer
							int retrn = rte_eth_tx_burst(ETHDEV_ID, 0, &rcv_pkt_bucket[i], 1);
							if (retrn != 1 && DEBUG) {
								RTE_LOG(INFO, USER1, "TX burst failed with error code %i.\n", retrn);
							}
							continue;

						} else if (ppplcp->code == CODE_ECHO_REP) {
							if (DEBUG) {
								RTE_LOG(INFO, USER1, "=> Echo-reply Packet received\n");
							}
							rte_pktmbuf_free(pkt);
							continue;

						} else if (ppplcp->code == CODE_CONF_ACK){
							if (DEBUG) {
								RTE_LOG(INFO, USER1, "=> Configure-ACK Packet received\n");
							}
							rte_pktmbuf_free(pkt);
							continue;

						}

					//check if it is a PAP packet
					} else if (__bswap_16(pppptcl->protocol) == PROTO_PAP) {
						if (DEBUG) {
							RTE_LOG(INFO, USER1, "=> PAP Packet received\n");
						}

						PPPPapReq * ppppapr;
						ppppapr = rte_pktmbuf_mtod_offset(pkt, PPPPapReq *, sizeof(PPPoEEncap)+seen);
						seen += sizeof(PPPPapReq);
						char user_name[ETH_JUMBO_LEN];
						char user_passwd[ETH_JUMBO_LEN];

						//get the username and password
						if (ppppapr->code == CODE_AUT_REQ) {

							//get the username
							uint8_t * u_len = rte_pktmbuf_mtod_offset(pkt, uint8_t *, sizeof(PPPoEEncap)+seen);
							uint8_t user_length = 0;
							memcpy(&user_length, u_len, sizeof(uint8_t));
							seen += sizeof(uint8_t);
							char * user = rte_pktmbuf_mtod_offset(pkt, char *, sizeof(PPPoEEncap)+seen);
							memcpy(user_name, user, user_length);
							seen += user_length;

							//get the password
							uint8_t * p_len = rte_pktmbuf_mtod_offset(pkt, uint8_t *, sizeof(PPPoEEncap)+seen);
							uint8_t passwd_length = 0;
							memcpy(&passwd_length, p_len, sizeof(uint8_t));
							seen += sizeof(uint8_t);
							char * passwd = rte_pktmbuf_mtod_offset(pkt, char *, sizeof(PPPoEEncap)+seen);
							memcpy(user_passwd, passwd, passwd_length);
							if (DEBUG) {
								RTE_LOG(INFO, USER1, "=> username = %s, password = %s\n", user_name, user_passwd);
							}
							
						}

						//authenticate the username and password
						//int result = auth(u, u_len, p, p_len);
						int result = 1;
						if (!result) {
							//send AUTH NAK
						} else {
							//send AUTH ACK
							send_auth_ack((uint16_t)1234, pppoee->l2hdr.s_addr);
						}
						
						memset(&user_name[0], 0, sizeof(user_name));
						memset(&user_passwd[0], 0, sizeof(user_passwd));
						rte_pktmbuf_free(pkt);
						continue;

					//check if it is a compression control protocol, we reject protocol = no compression
					} else if (__bswap_16(pppptcl->protocol) == PROTO_CCP) {

						if (DEBUG) {
							RTE_LOG(INFO, USER1, "=> CCP Packet received\n");
						}

						//send a protocol reject
						send_proto_reject((uint16_t)PROTO_CCP, pkt);
						rte_pktmbuf_free(pkt);
						continue;
					} else if (__bswap_16(pppptcl->protocol) == PROTO_IPCP) {

						PPPIpcp * pppipcp;
						pppipcp = rte_pktmbuf_mtod_offset(pkt, PPPIpcp *, sizeof(PPPoEEncap)+seen);
						seen += sizeof(PPPIpcp);
						PPPIpcpUsed * ipDns;
						int type = 0;


char ethr[50];
ethaddr_to_string(ethr, &(pppoee->l2hdr.s_addr));
RTE_LOG(INFO, USER1, "=> ether src %s\n", ethr);
						//check if it is IPCP request
						if (pppipcp->code == CODE_IPCP_REQ) {

							//check if ip is set for the session, if not, set it now
							ipDns = get_ip_dns();

							unsigned int optseen = 0;
							unsigned int len = __bswap_16(pppipcp->length)-4;
							PPPIpcpOptions * pppipcpo;
							//parse IPCP options in the packet
							while (optseen < len) {
								pppipcpo = rte_pktmbuf_mtod_offset(pkt, PPPIpcpOptions *, sizeof(PPPoEEncap)+seen+optseen);
								optseen += sizeof(PPPIpcpOptions);
								//search for ip
								if (pppipcpo->type == TYPE_IP) {
									if (pppipcpo->value == ipDns->ip) {
										type = 2;
									} else {
										pppipcpo->value = ipDns->ip;
										type = 3;
									}
								//search for primary dns
								} else if (pppipcpo->type == TYPE_DNS_PRI) {
									if (pppipcpo->value == ipDns->dns1) {
										type = 2;
									} else {
										pppipcpo->value = ipDns->dns1;
										type = 3;
									}
								//search for secondary dns
								} else if (pppipcpo->type == TYPE_DNS_SEC) {
									if (pppipcpo->value == ipDns->dns2) {
										type = 2;
									} else {
										pppipcpo->value = ipDns->dns2;
										type = 3;
									}
                                        			} else {
									if (DEBUG) {
										RTE_LOG(INFO, USER1, "=> Unknown option found in IPCP packet received...%x\n", pppipcpo->type);
									}
                                        			}
							}

							//send ACK to peer
							if (type == 2) {
								pppipcp->code = CODE_IPCP_ACK;
							//send NAK to peer
							} else if (type == 3) {
								pppipcp->code = CODE_IPCP_NAK;
							} else {
								if (DEBUG) {
									RTE_LOG(INFO, USER1, "=> No type set for IPCP packet received. dropping....\n");
								}
								rte_pktmbuf_free(pkt);
								continue;
							}

							memcpy(&pppoee->l2hdr.d_addr, &pppoee->l2hdr.s_addr, sizeof(struct ether_addr));
                                			memcpy(&pppoee->l2hdr.s_addr, &srtointra_addr, sizeof(struct ether_addr));
							//send the packet
							int retrn = rte_eth_tx_burst(ETHDEV_ID, 0, &rcv_pkt_bucket[i], 1);
							if (retrn != 1 && DEBUG) {
								RTE_LOG(INFO, USER1, "TX burst failed with error code %i.\n", retrn);
							}

							//send a ip request back
							if (type == 2) {
								send_ip_req(ipDns->ip, pkt);
							}
							continue;

						} else if (pppipcp->code == CODE_IPCP_ACK) {
							if (DEBUG) {
								RTE_LOG(INFO, USER1, "=> IPCP-ACK Packet received\n");
							}
							rte_pktmbuf_free(pkt);
							continue;
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


/*
 *Function to send a config request
 */
void send_config_req(uint8_t type, uint16_t session_id, struct ether_addr client_l2addr) {

	if (DEBUG) {
		RTE_LOG(INFO, USER1, "=> called send_config_req for type %i.\n", (int) type);
	}
	//generate a PPPoE packet
	struct rte_mbuf * acpkt = rte_pktmbuf_alloc(mempool);
	PPPoEEncap * pppoeer = (PPPoEEncap *) rte_pktmbuf_append(acpkt, sizeof(PPPoEEncap));
        memcpy(&pppoeer->l2hdr.d_addr, &client_l2addr, sizeof(struct ether_addr));
        memcpy(&pppoeer->l2hdr.s_addr, &srtointra_addr, sizeof(struct ether_addr));
	pppoeer->l2hdr.ether_type = __bswap_16(ETHER_SESSION);
        pppoeer->ver = PPPOE_VER;
        pppoeer->type = PPPOE_TYPE;
        pppoeer->session = __bswap_16(session_id);
	pppoeer->code = CODE_SESS;
        pppoeer->length = 0;

	uint16_t pppoe_payload_legth = 0;
	PPPEncap * pppptcls = (PPPEncap *) rte_pktmbuf_append(acpkt, sizeof(PPPEncap));
	pppptcls->protocol = __bswap_16(PROTO_LCP);
	pppoe_payload_legth += (uint16_t) sizeof(PPPEncap);

	PPPLcp * ppplcps = (PPPLcp *) rte_pktmbuf_append(acpkt, sizeof(PPPLcp));
	ppplcps->code = CODE_CONF_REQ;
	//for now keep a temp id
	ppplcps->identifier = 0x04;
	ppplcps->length = 0;
	uint16_t ppplcp_length = 0;
	pppoe_payload_legth += (uint16_t) sizeof(PPPLcp);
	ppplcp_length += (uint16_t) sizeof(PPPLcp);
	
	//check if for auth configure-request
	if (type == TYPE_AUP) {

		//add options
		PPPLcpOptionsGenl * ppplcpos = (PPPLcpOptionsGenl *) rte_pktmbuf_append(acpkt, sizeof(PPPLcpOptionsGenl));
		ppplcpos->type = TYPE_AUP;
		ppplcpos->length = 0x04; //will always be 4 bytes long
		ppplcpos->value = __bswap_16(PROTO_PAP);
		pppoe_payload_legth += (uint16_t) sizeof(PPPLcpOptionsGenl);
		ppplcp_length += (uint16_t) ppplcpos->length;

		PPPLcpOptionsMagic * magic = (PPPLcpOptionsMagic *) rte_pktmbuf_append(acpkt, sizeof(PPPLcpOptionsMagic));
		magic->type = TYPE_MGN;
                magic->length = 0x06; //will always be 6 bytes long
		//for now add a temp magic no:
                magic->value = __bswap_16(0x12345678);
                pppoe_payload_legth += (uint16_t) sizeof(PPPLcpOptionsMagic);
		ppplcp_length += (uint16_t) magic->length;
	} else {
		RTE_LOG(INFO, USER1, "Request for sending unknown configure-request, not sending...\n");
		rte_pktmbuf_free(acpkt);
		return;
	}

	ppplcps->length = __bswap_16(ppplcp_length);
        pppoeer->length = __bswap_16(pppoe_payload_legth);
	//send the packet
	int retrn = rte_eth_tx_burst(ETHDEV_ID, 0, &acpkt, 1);
	if (retrn != 1 && DEBUG) {
  		RTE_LOG(INFO, USER1, "TX burst failed with error code %i.\n", retrn);
       	}
}


/*
 *Function to send an Echo-request
 */
void send_echo_req(uint16_t session_id, struct ether_addr client_l2addr) {

	if (DEBUG) {
		RTE_LOG(INFO, USER1, "=> called send_echo_req\n");
	}
	//generate a PPPoE packet

	struct rte_mbuf * acpkt = rte_pktmbuf_alloc(mempool);
	PPPoEEncap * pppoeer = (PPPoEEncap *) rte_pktmbuf_append(acpkt, sizeof(PPPoEEncap));
        memcpy(&pppoeer->l2hdr.d_addr, &client_l2addr, sizeof(struct ether_addr));
        memcpy(&pppoeer->l2hdr.s_addr, &srtointra_addr, sizeof(struct ether_addr));
	pppoeer->l2hdr.ether_type = __bswap_16(ETHER_SESSION);
        pppoeer->ver = PPPOE_VER;
        pppoeer->type = PPPOE_TYPE;
        pppoeer->session = __bswap_16(session_id);
	pppoeer->code = CODE_SESS;
        pppoeer->length = 0;

	uint16_t pppoe_payload_legth = 0;
	PPPEncap * pppptcls = (PPPEncap *) rte_pktmbuf_append(acpkt, sizeof(PPPEncap));
	pppptcls->protocol = __bswap_16(PROTO_LCP);
	pppoe_payload_legth += (uint16_t) sizeof(PPPEncap);

	PPPLcpMagic * ppplcpms = (PPPLcpMagic *) rte_pktmbuf_append(acpkt, sizeof(PPPLcpMagic));
	ppplcpms->code = CODE_ECHO_REQ;
	//for now keep a temp id
	ppplcpms->identifier = 0x05;
	ppplcpms->length = 0;
	//for now add a temp magic no:
	ppplcpms->magic_number = __bswap_16(0x12345668);
	uint16_t ppplcp_length = 0;
	pppoe_payload_legth += (uint16_t) sizeof(PPPLcpMagic);
	ppplcp_length += (uint16_t) sizeof(PPPLcpMagic);

	ppplcpms->length = __bswap_16(ppplcp_length);
        pppoeer->length = __bswap_16(pppoe_payload_legth);
	//send the packet
	int retrn = rte_eth_tx_burst(ETHDEV_ID, 0, &acpkt, 1);
	if (retrn != 1 && DEBUG) {
  		RTE_LOG(INFO, USER1, "TX burst failed with error code %i.\n", retrn);
       	}
}


/*
 *Function to send an Authentication ACK 
 */
void send_auth_ack(uint16_t session_id, struct ether_addr client_l2addr) {

	if (DEBUG) {
		RTE_LOG(INFO, USER1, "=> called send_auth_ack\n");
	}
	//generate a PPPoE packet
	struct rte_mbuf * acpkt = rte_pktmbuf_alloc(mempool);
	PPPoEEncap * pppoeer = (PPPoEEncap *) rte_pktmbuf_append(acpkt, sizeof(PPPoEEncap));
        memcpy(&pppoeer->l2hdr.d_addr, &client_l2addr, sizeof(struct ether_addr));
        memcpy(&pppoeer->l2hdr.s_addr, &srtointra_addr, sizeof(struct ether_addr));
	pppoeer->l2hdr.ether_type = __bswap_16(ETHER_SESSION);
        pppoeer->ver = PPPOE_VER;
        pppoeer->type = PPPOE_TYPE;
        pppoeer->session = __bswap_16(session_id);
	pppoeer->code = CODE_SESS;
        pppoeer->length = 0;

	uint16_t pppoe_payload_legth = 0;
	PPPEncap * pppptcls = (PPPEncap *) rte_pktmbuf_append(acpkt, sizeof(PPPEncap));
	pppptcls->protocol = __bswap_16(PROTO_PAP);
	pppoe_payload_legth += (uint16_t) sizeof(PPPEncap);

	PPPPapAck * ppppapas = (PPPPapAck *) rte_pktmbuf_append(acpkt, sizeof(PPPPapAck));
	ppppapas->code = CODE_AUT_ACK;
	//for now add some identifier
	ppppapas->identifier = 0x05;
	ppppapas->length = 0;
	ppppapas->idms_length = 0;
	uint16_t ppppap_length = 0;
	pppoe_payload_legth += (uint16_t) sizeof(PPPPapAck);
	ppppap_length += (uint16_t) sizeof(PPPPapAck);

	ppppapas->length = __bswap_16(ppppap_length);
        pppoeer->length = __bswap_16(pppoe_payload_legth);
	//send the packet
	int retrn = rte_eth_tx_burst(ETHDEV_ID, 0, &acpkt, 1);
	if (retrn != 1 && DEBUG) {
  		RTE_LOG(INFO, USER1, "TX burst failed with error code %i.\n", retrn);
       	}
}


/*
 *Function to send a protocol reject 
 */
void send_proto_reject(uint16_t type, struct rte_mbuf* pkt) {

	if (DEBUG) {
		RTE_LOG(INFO, USER1, "=> called send_auth_ack\n");
	}
	//generate a PPPoE packet
	struct rte_mbuf * acpkt = rte_pktmbuf_alloc(mempool);
	PPPoEEncap * pppoeer = (PPPoEEncap *) rte_pktmbuf_append(acpkt, sizeof(PPPoEEncap));
	PPPoEEncap * pppoeeg = rte_pktmbuf_mtod(pkt, PPPoEEncap *);
	memcpy(pppoeer, pppoeeg, sizeof(PPPoEEncap));
	memcpy(&pppoeer->l2hdr.d_addr, &pppoeer->l2hdr.s_addr, sizeof(struct ether_addr));
        memcpy(&pppoeer->l2hdr.s_addr, &srtointra_addr, sizeof(struct ether_addr));
	pppoeer->length = 0;

	uint16_t pppoe_payload_legth = 0;
	PPPEncap * pppptcls = (PPPEncap *) rte_pktmbuf_append(acpkt, sizeof(PPPEncap));
	pppptcls->protocol = __bswap_16(PROTO_LCP);
	pppoe_payload_legth += (uint16_t) sizeof(PPPEncap);

	PPPLcpRjct * ppplcprjct = (PPPLcpRjct *) rte_pktmbuf_append(acpkt, sizeof(PPPLcpRjct));
	ppplcprjct->code = CODE_PROT_REJ;
	//for now add some identifier
	ppplcprjct->identifier = 0x05;
	ppplcprjct->length = 0;
	ppplcprjct->protocol = __bswap_16(type);
	uint16_t pppprjct_length = 0;
	pppoe_payload_legth += (uint16_t) sizeof(PPPLcpRjct);
	pppprjct_length += (uint16_t) sizeof(PPPLcpRjct);

	char * infog = rte_pktmbuf_mtod_offset(pkt, char *, (sizeof(PPPoEEncap)+sizeof(PPPEncap)));
	unsigned int info_len = __bswap_16(pppoeeg->length)-sizeof(PPPEncap);
	char * infor = (char *) rte_pktmbuf_append(acpkt, info_len);
	memcpy(infor, infog, info_len);
	pppoe_payload_legth += info_len;
	pppprjct_length += info_len;

	ppplcprjct->length = __bswap_16(pppprjct_length);
        pppoeer->length = __bswap_16(pppoe_payload_legth);
	//send the packet
	int retrn = rte_eth_tx_burst(ETHDEV_ID, 0, &acpkt, 1);
	if (retrn != 1 && DEBUG) {
  		RTE_LOG(INFO, USER1, "TX burst failed with error code %i.\n", retrn);
       	}
}


/*
 *Function to send a ip request
 *This function should be called after swapping the mac addresses to send back 
 */
void send_ip_req(uint32_t ip, struct rte_mbuf* pkt) {

	if (DEBUG) {
		RTE_LOG(INFO, USER1, "=> called send_ip_req\n");
	}
	//generate a PPPoE packet
	struct rte_mbuf * acpkt = rte_pktmbuf_alloc(mempool);
	PPPoEEncap * pppoeer = (PPPoEEncap *) rte_pktmbuf_append(acpkt, sizeof(PPPoEEncap));
	PPPoEEncap * pppoeeg = rte_pktmbuf_mtod(pkt, PPPoEEncap *);
	memcpy(pppoeer, pppoeeg, sizeof(PPPoEEncap));
	pppoeer->length = 0;

	uint16_t pppoe_payload_legth = 0;
	PPPEncap * pppptcls = (PPPEncap *) rte_pktmbuf_append(acpkt, sizeof(PPPEncap));
	pppptcls->protocol = __bswap_16(PROTO_IPCP);
	pppoe_payload_legth += (uint16_t) sizeof(PPPEncap);

	PPPIpcp * pppipcp = (PPPIpcp *) rte_pktmbuf_append(acpkt, sizeof(PPPIpcp));
	pppipcp->code = CODE_IPCP_REQ;
	//for now add some identifier
	pppipcp->identifier = 0x05;
	pppipcp->length = 0;
	uint16_t pppipcp_length = 0;
	pppoe_payload_legth += (uint16_t) sizeof(PPPIpcp);
	pppipcp_length += (uint16_t) sizeof(PPPIpcp);

	PPPIpcpOptions * optn = (PPPIpcpOptions *) rte_pktmbuf_append(acpkt, sizeof(PPPIpcpOptions));	
	optn->type = TYPE_IP;
	optn->length = 6; //always will be 6	
	optn->value = 0x0500000a;
	pppoe_payload_legth += (uint16_t) sizeof(PPPIpcpOptions);
	pppipcp_length += (uint16_t) sizeof(PPPIpcpOptions);

	pppipcp->length = __bswap_16(pppipcp_length);
        pppoeer->length = __bswap_16(pppoe_payload_legth);
	//send the packet
	int retrn = rte_eth_tx_burst(ETHDEV_ID, 0, &acpkt, 1);
	if (retrn != 1 && DEBUG) {
  		RTE_LOG(INFO, USER1, "TX burst failed with error code %i.\n", retrn);
       	}
}
