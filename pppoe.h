/***********************************************************
 *User configurable parameters
 *Recompile after a change 
 ***********************************************************/

//#define SERVICE_NAME 	"SRNAME"
//#define AC_NAME		"ACNAME"

unsigned char * service_name 	= "SRNAME";
unsigned char * ac_name		= "ACNAME";

//debug option, 0 to unset, 1 to set
#define DEBUG		1

//server to intranet ethernet address
const struct ether_addr srtointra_addr = {.addr_bytes={0x08,0x00,0x27,0xa5,0xe0,0x94}};

//to be removed
const struct ether_addr tasks_addr = {.addr_bytes={0x08,0x00,0x27,0xa5,0xe0,0x94}};
const struct ether_addr task2_addr = {.addr_bytes={0x0a,0x00,0x27,0x00,0x00,0x00}};
const struct ether_addr task3_addr = {.addr_bytes={0x00,0x15,0x17,0x03,0x00,0x03}};

//Authentication protocol, 0 for PAP, 1 for CHAP (currently PAP only)
#define AUTH_PROTO	0

/***********************************************************
 *Server specific declarations
 *Do not modify any structures 
 ***********************************************************/

extern struct rte_mempool* mempool;

#define BURSTLEN	4
#define ETH_JUMBO_LEN	20

//ETHER_TYPE fields
#define ETHER_DISCOVERY	0x8863
#define ETHER_SESSION	0x8864

//PPPoE version and type
#define PPPOE_VER	0x01
#define PPPOE_TYPE	0x01

//PPPoE codes
#define CODE_PADI	0x09
#define CODE_PADO	0x07
#define CODE_PADR	0x19	
#define CODE_PADS	0x65
#define CODE_PADT	0xa7
#define CODE_SESS	0x00

//PPPoE encapsulation structure
typedef struct __attribute__((__packed__)) {
	struct ether_hdr l2hdr;
	unsigned int type:4;
	unsigned int ver:4;
	unsigned int code:8;
	unsigned int session:16;
	unsigned int length:16;
} PPPoEEncap;

//PPPoE tag types
#define TYPE_END_OF_LIST 	0x0000
#define TYPE_SERVICE_NAME 	0x0101
#define TYPE_AC_NAME		0x0102
#define	TYPE_HOST_UNIQ		0x0103
#define TYPE_AC_COOKIE		0x0104
#define	TYPE_VENDOR_SPECIFIC 	0x0105
#define TYPE_RELAY_SESSION_ID 	0x0110
#define TYPE_SERVICE_NAME_ERROR	0x0201
#define TYPE_AC_SYSTEM_ERROR	0x0202
#define TYPE_GENERIC_ERROR	0x0203

//PPPoE tag structure
typedef struct __attribute__((__packed__)) {
	unsigned int type:16;
	unsigned int length:16;
} PPPoETag;

//PPP protocols
#define PROTO_LCP	0xc021
#define	PROTO_PAP	0xc023
#define	PROTO_LQR	0xc025
#define	PROTO_CHAP	0xc223
#define	PROTO_CCP	0x80fd
#define	PROTO_IPCP	0x8021

//PPP eccapsulation structure
typedef struct __attribute__((__packed__)) {
	unsigned int protocol:16;
} PPPEncap;

//PPP lcp codes
#define CODE_CONF_REQ	0x01
#define CODE_CONF_ACK	0x02
#define CODE_CONF_NAK	0x03
#define CODE_CONF_REJ	0x04
#define CODE_TERM_REQ	0x05
#define CODE_TERM_ACK	0x06
#define CODE_CODE_REJ	0x07
#define CODE_PROT_REJ	0x08
#define CODE_ECHO_REQ	0x09
#define CODE_ECHO_REP	0x0a
#define CODE_DISC_REQ	0x0b 

//PPP LCP structure
typedef struct __attribute__((__packed__)) {
	unsigned int code:8;
	unsigned int identifier:8;
	unsigned int length:16;
} PPPLcp;

//PPP LCP Echo structure
typedef struct __attribute__((__packed__)) {
	unsigned int code:8;
	unsigned int identifier:8;
	unsigned int length:16;
	unsigned int magic_number:32;
} PPPLcpMagic;

//PPP LCP reject structure
typedef struct __attribute__((__packed__)) {
	unsigned int code:8;
	unsigned int identifier:8;
	unsigned int length:16;
	unsigned int protocol:16;
} PPPLcpRjct;

//PPP LCP option types
#define TYPE_MRU	0x01
#define TYPE_AUP	0x03
#define TYPE_QUP	0x04
#define TYPE_MGN	0x05
#define TYPE_PFC	0x07
#define TYPE_ACC	0x08

//PPP LCP options
typedef struct __attribute__((__packed__)) {
	unsigned int type:8;
	unsigned int length:8;
} PPPLcpOptions;

//PPP LCP options general structure
typedef struct __attribute__((__packed__)) {
	unsigned int type:8;
	unsigned int length:8;
	unsigned int value:16;
} PPPLcpOptionsGenl;

//PPP LCP options magic structure
typedef struct __attribute__((__packed__)) {
        unsigned int type:8;
        unsigned int length:8;
        unsigned int value:32;
} PPPLcpOptionsMagic;

//PPP PAP codes
#define CODE_AUT_REQ	0x01
#define CODE_AUT_ACK	0x02
#define CODE_AUT_NAK	0x03

//PPP PAP REQ structure
typedef struct __attribute__((__packed__)) {
	unsigned int code:8;
	unsigned int identifier:8;
	unsigned int length:16;
} PPPPapReq;

//PPP PAP ACK structure
typedef struct __attribute__((__packed__)) {
	unsigned int code:8;
	unsigned int identifier:8;
	unsigned int length:16;
	unsigned int idms_length:8;
} PPPPapAck;

//PPP IPCP codes
#define CODE_IPCP_REQ	0x01
#define CODE_IPCP_ACK	0x02
#define CODE_IPCP_NAK	0x03

//PPP IPCP structure
typedef struct __attribute__((__packed__)) {
	unsigned int code:8;
	unsigned int identifier:8;
	unsigned int length:16;
} PPPIpcp;

//PPP IPCP options
#define TYPE_IP		0x03
#define TYPE_DNS_PRI	0x81
#define TYPE_DNS_SEC	0x83

//PPP IPCP options structure
typedef struct __attribute__((__packed__)) {
        unsigned int type:8;
        unsigned int length:8;
        unsigned int value:32;
} PPPIpcpOptions;

//PPP IPCP used values structure
typedef struct __attribute__((__packed__)) {
        uint32_t ip;
        uint32_t dns1;
        uint32_t dns2;
} PPPIpcpUsed;

//session states
#define STATE_SESS_CRTD		0x00
#define STATE_PADS_SENT		0x01
#define STATE_CONF_AUTH_SENT	0x02
#define	STATE_AUTH_ACK_SENT	0x03
#define STATE_AUTH_ECHO_SENT	0x04

//connection index structure per session
struct conn_index {
	unsigned int index;
	struct conn_index * next;
};

//session structure
typedef struct __attribute__((__packed__)) {
	unsigned int state:8;
	struct ether_addr client_mac_addr;
	uint32_t client_ipv4_addr;
	unsigned int session_id:16;
	struct conn_index * index;
	unsigned int auth_ident:8;
	unsigned int echo_ident:8;
	unsigned int mru;
} Session;

//functions
void send_config_req(uint8_t type, uint16_t session_id, struct ether_addr client_l2addr);
void send_echo_req(uint16_t session_id, struct ether_addr client_l2addr);
void send_auth_ack(uint16_t session_id, struct ether_addr client_l2addr);
void send_proto_reject(uint16_t type, struct rte_mbuf * pkt);
PPPIpcpUsed * get_ip_dns();
void send_ip_req(uint32_t ip, struct rte_mbuf* pkt);
