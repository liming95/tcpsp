/*
 * TCPSP -	TCP Splicing
 *
 * Copyright (C) 2002 Wensong Zhang <wensong@linux-vs.org>
 *
 * tcpsp.h:	main structure definitions and function prototypes
 */

#ifndef _TCPSP_H
#define _TCPSP_H

#include <asm/types.h>          /* For __uXX types */

#define TCPSP_VERSION_CODE            0x000005
#define NVERSION(version)                       \
	(version >> 16) & 0xFF,                 \
	(version >> 8) & 0xFF,                  \
	version & 0xFF

/*
 *      TCPSP socket options
 */
#define TCPSP_BASE_CTL		(64+1024+64+64+64)	/* base */

#define TCPSP_SO_SET_NONE	TCPSP_BASE_CTL	        /* just peek */
#define TCPSP_SO_SET_ADD	(TCPSP_BASE_CTL+1)
#define TCPSP_SO_SET_MAX	TCPSP_SO_SET_ADD

#define TCPSP_SO_GET_VERSION	TCPSP_BASE_CTL
#define TCPSP_SO_GET_INFO	(TCPSP_BASE_CTL+1)
#define TCPSP_SO_GET_MAX	TCPSP_SO_GET_INFO


/* The argument to TCPSP_SO_SET_ADD */
typedef struct splice_conn_s {
	int s1;

	int s2;

	/* the number of bytes written to s2 */
	int n;
} splice_conn_t;


/*
 *      TCPSP Connection Flags
 */
#define TCPSP_CONN_F_FWD_MASK         0x0007    /* mask for the fwd methods */
#define TCPSP_CONN_F_MASQ	      0x0000    /* masquerading */
#define TCPSP_CONN_F_LOCALNODE	      0x0001    /* local node */
#define TCPSP_CONN_F_TUNNEL	      0x0002    /* tunneling */
#define TCPSP_CONN_F_DROUTE           0x0003    /* direct routing */
#define TCPSP_CONN_F_BYPASS           0x0004    /* cache bypass */
#define TCPSP_CONN_F_HASHED	      0x0040	/* hashed entry */
#define TCPSP_CONN_F_NOOUTPUT         0x0080    /* no output packets */
#define TCPSP_CONN_F_INACTIVE         0x0100    /* not established */
#define TCPSP_CONN_F_OUT_SEQ          0x0200    /* must do output seq adjust */
#define TCPSP_CONN_F_IN_SEQ           0x0400    /* must do input seq adjust */
#define TCPSP_CONN_F_SEQ_MASK         0x0600    /* in/out sequence mask */
#define TCPSP_CONN_F_NO_CPORT         0x0800    /* no client port set yet */


#define TCPSP_SCHEDNAME_MAXLEN         16
#define TCPSP_IFNAME_MAXLEN            16


#ifdef __KERNEL__

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
#include <linux/config.h>
#endif

#include <linux/list.h>                 /* for struct list_head */
#include <linux/spinlock.h>             /* for struct rwlock_t */
#include <linux/skbuff.h>               /* for struct sk_buff */
#include <linux/ip.h>                   /* for struct iphdr */
#include <asm/atomic.h>                 /* for struct atomic_t */
#include <net/route.h>			/* for ip_route_output */
#include <net/tcp.h>
#include <net/udp.h>

#define CONFIG_TCPSP_DEBUG

#ifdef CONFIG_TCPSP_DEBUG
extern int tcpsp_get_debug_level(void);
#define TCPSP_DBG(level, msg...)			\
    do {						\
	    if (level <= tcpsp_get_debug_level())	\
		    printk(KERN_DEBUG "TCPSP: " msg);	\
    } while (0)
#define TCPSP_DBG_RL(msg...)				\
    do {						\
	    if (net_ratelimit())			\
		    printk(KERN_DEBUG "TCPSP: " msg);	\
    } while (0)
#else	/* NO DEBUGGING at ALL */
#define TCPSP_DBG(level, msg...)  do {} while (0)
#define TCPSP_DBG_RL(msg...)  do {} while (0)
#endif

#define TCPSP_BUG() BUG()
#define TCPSP_ERR(msg...) printk(KERN_ERR "TCPSP: " msg)
#define TCPSP_INFO(msg...) printk(KERN_INFO "TCPSP: " msg)
#define TCPSP_WARNING(msg...) \
	printk(KERN_WARNING "TCPSP: " msg)
#define TCPSP_ERR_RL(msg...)				\
    do {						\
	    if (net_ratelimit())			\
		    printk(KERN_ERR "TCPSP: " msg);	\
    } while (0)

#ifdef CONFIG_TCPSP_DEBUG
#define EnterFunction(level)						\
    do {								\
	    if (level <= tcpsp_get_debug_level())			\
		    printk(KERN_DEBUG "Enter: %s, %s line %i\n",	\
			   __FUNCTION__, __FILE__, __LINE__);		\
    } while (0)
#define LeaveFunction(level)                                            \
    do {                                                                \
	    if (level <= tcpsp_get_debug_level())                       \
			printk(KERN_DEBUG "Leave: %s, %s line %i\n",    \
			       __FUNCTION__, __FILE__, __LINE__);       \
    } while (0)
#else
#define EnterFunction(level)   do {} while (0)
#define LeaveFunction(level)   do {} while (0)
#endif


/*
 *      TCPSP State Values
 */
enum {
	TCPSP_S_NONE = 0,
	TCPSP_S_ESTABLISHED,
	TCPSP_S_SYN_SENT,
	TCPSP_S_SYN_RECV,
	TCPSP_S_FIN_WAIT,
	TCPSP_S_TIME_WAIT,
	TCPSP_S_CLOSE,
	TCPSP_S_CLOSE_WAIT,
	TCPSP_S_LAST_ACK,
	TCPSP_S_LISTEN,
	TCPSP_S_SYNACK,
	TCPSP_S_LAST
};


struct tcpsp_timeout_table {
	atomic_t refcnt;
	int scale;
	int timeout[TCPSP_S_LAST+1];
};


struct conn_tuple {
	__u32                   laddr;		/* locate address */
	__u32                   raddr;          /* remote address */
	__u16                   lport;
	__u16                   rport;

	/* sequence numbers at the spliced point */
	__u32			splice_iss;	/* initial send sequence */
	__u32			splice_irs;	/* initial receive sequence */

	/* tcp timestamps at the spliced point*/
	__u32			splice_tsv;	/* timestamp value */
	__u32			splice_tse;	/* timestamp echo reply */
	char			timestamp_ok;
};


/* direction definition */
#define FROM_FIRST_CONN		0
#define FROM_SECOND_CONN	1

/*
 *	TCP splicing connection
 */
struct tcpsp_conn {
	struct list_head        f_list;		/* first hash table */
	struct list_head        s_list;		/* second hash table */

	atomic_t                refcnt;		/* reference count */

	/* two sockets/connections */
	struct socket		*socket[2];
	atomic_t		need_rst;	/* need resetting socks */
	struct conn_tuple	conn[2];	/* two spliced connections */

	/* Flags and state transition */
	spinlock_t              lock;           /* lock for state transition */
	volatile __u16          flags;          /* status flags */
	volatile __u16          state;          /* state info */

	/* timeout */
	volatile unsigned long  timeout;
	struct tcpsp_timeout_table *timeout_table;
	struct timer_list       timer;		/* expiration timer */

	/* packet transmitter */
	int (*packet_xmit)(struct sk_buff *skb);
};


/*
 *      TCPSP core functions
 *      (from tcpsp_core.c)
 */
extern const char *tcpsp_proto_name(unsigned proto);


/*
 *     tcpsp_conn handling functions
 *     (from tcpsp_conn.c)
 */
extern struct tcpsp_timeout_table tcpsp_timeout_tbl;

/* TCPSP connection entry hash table */
#ifndef CONFIG_TCPSP_TAB_BITS
#define CONFIG_TCPSP_TAB_BITS   8
#endif
#define TCPSP_CONN_TAB_BITS     CONFIG_TCPSP_TAB_BITS
#define TCPSP_CONN_TAB_SIZE     (1 << TCPSP_CONN_TAB_BITS)
#define TCPSP_CONN_TAB_MASK     (TCPSP_CONN_TAB_SIZE - 1)

extern struct tcpsp_conn *
tcpsp_conn_get(__u32 saddr, __u16 sport, __u32 daddr, __u16 dport, int *dir);

/* put back the conn without restarting its timer */
static inline void __tcpsp_conn_put(struct tcpsp_conn *cp)
{
	atomic_dec(&cp->refcnt);
}
extern void tcpsp_conn_put(struct tcpsp_conn *cp);

extern struct tcpsp_conn *
tcpsp_conn_new(struct socket *sock1, struct socket *sock2, int n);
#define tcpsp_conn_expire_now(cp)  cp->timer.function((struct timer_list*) cp)

extern const char * tcpsp_state_name(int state);
extern int tcpsp_set_state(struct tcpsp_conn *cp, int direction,
			   struct iphdr *iph, struct tcphdr *th);
extern int tcpsp_conn_init(void);
extern void tcpsp_conn_cleanup(void);

/*
 *      TCPSP control data and functions
 *      (from tcpsp_ctl.c)
 */
extern int tcpsp_control_init(void);
extern void tcpsp_control_cleanup(void);


#endif /* __KERNEL__ */

#endif	/* _TCPSP_H */
