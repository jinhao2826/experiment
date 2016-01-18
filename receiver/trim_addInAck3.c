#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <net/tcp.h>
#include <net/ip.h>
#include <linux/spinlock.h>

#define capability_len 60

spinlock_t mylock = __SPIN_LOCK_UNLOCKED(mylock);
static struct nf_hook_ops nfho;
static struct nf_hook_ops nfho2;


struct analyze{
	unsigned int id;
	char code[capability_len - 4];

};

struct capability{
	char code[capability_len];
	struct capability * next;
};


struct capabilityheader{
        unsigned int saddr;
        struct capability *first;  
		struct capability *end;
		struct capabilityheader *next;

};


struct capabilityheader * header = NULL;
struct capabilityheader * tail = NULL;



struct capabilityheader *searchcapabilityheader(unsigned int addr){

	struct capabilityheader *q = header;
	while(q != NULL && q->saddr != addr){
		q = q->next;

	}

	return q;

}


unsigned int ip_str_to_num(const char *buf)
{

    unsigned int tmpip[4] = {0};
    unsigned int tmpip32 = 0;
    sscanf(buf, "%d.%d.%d.%d", &tmpip[0], &tmpip[1], &tmpip[2], &tmpip[3]);
    tmpip32 = (tmpip[3]<<24) | (tmpip[2]<<16) | (tmpip[1]<<8) | tmpip[0];
    return tmpip32;
}


/*function to be called by hook*/
unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	char middlebox_ip[15] = "192.168.1.102";
	char redirect_ip[15] = "192.168.1.102";
	struct iphdr *iph = NULL;
	struct tcphdr *tcph=NULL;
	int tcplen;
	unsigned int middlebox_networkip;
	unsigned int redirect_networkip;

	struct capability *p = NULL;
	struct capabilityheader *h = NULL;

	struct analyze *a = NULL;
	
	iph = ip_hdr(skb);

	middlebox_networkip = ip_str_to_num(middlebox_ip);
	redirect_networkip = ip_str_to_num(redirect_ip);


    if(iph->protocol == IPPROTO_TCP)
	{
		tcph = (struct tcphdr *)((__u32 *)iph+ iph->ihl);	
		tcplen = skb->len - ip_hdrlen(skb);

		if(iph->daddr == redirect_networkip && ntohs(tcph->dest) == 9877 && tcph->res1 == 0xf)
		{
			
			//printk(KERN_INFO "user data:%0x skb_len:%u skb->data:%p skb->tail:%p\n", (unsigned char *)skb->tail - (unsigned char *)skb->data, skb->len, (unsigned char *)skb->data, (unsigned char *)skb->tail);
			//printk(KERN_INFO "TRIM===>Before:len:%0x tailroom:%0x head:%0x data:%0x tail:%0x end:%0x data_len:%0x\n", skb->len,skb->end-skb->tail, skb->head,skb->data, skb->tail, skb->end, skb->data_len);
			
			spin_lock(&mylock);

			h = searchcapabilityheader(iph->saddr);
			if (h == NULL){
				if ((h = kmalloc(sizeof(struct capabilityheader), GFP_KERNEL)) != NULL){
					printk(KERN_INFO "malloc and create capability header.\n");
					h->saddr = iph->saddr;
					h->first = NULL;
					h->end = NULL;
					h->next = NULL;
					
				}else{
					printk(KERN_INFO "malloc failed.\n");
				}

				if(header == NULL){
					header = h;
					tail = h;
			
				}else{

					tail->next = h;
					tail = h;

				}
			}

			
			if ((p = kmalloc(sizeof(struct capability), GFP_KERNEL)) != NULL){
				memcpy(p->code, (skb->data + skb->len - capability_len), capability_len);
				
				a = (struct analyze *)p->code;
				printk(KERN_INFO "kmalloc and copy into a->id=%u a->code=%s\n", a->id, a->code);

				p->next = NULL;
			}			
			
			if( h->first == NULL)
			{
				h->first = p;
				h->end = p;

			}else {

				h->end->next = p;
				h->end = p;
			}
			spin_unlock(&mylock);

			skb_trim(skb, skb->len - capability_len);

			//printk(KERN_INFO "TRIM===>After: len:%u tailroom:%0x head:%0x data:%0x tail:%0x end:%0x\n", skb->len, skb->end-skb->tail, skb->head,skb->data, skb->tail, skb->end);

			
			//printk(KERN_INFO "2#tail room:%u skb_len:%u\n", skb->end - skb->tail, skb->len);

			iph->tot_len = iph->tot_len - htons(capability_len);
			tcplen = skb->len - ip_hdrlen(skb);
			tcph->check = 0; 
			//tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial(tcph, tcph->doff << 2, skb->csum));
			tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial(tcph, tcplen, 0));
			skb->ip_summed = CHECKSUM_NONE;
			ip_send_check(iph);
		}
		
	
 	}
	return NF_ACCEPT;                                                              
}


/*function to be called by hook*/

unsigned int hook_func2(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	char middlebox_ip[15] = "192.168.1.102";
	char redirect_ip[15] = "192.168.1.102";
	struct iphdr *iph = NULL;
	struct tcphdr *tcph=NULL;
	int tcplen;
	unsigned int middlebox_networkip;
	unsigned int redirect_networkip;
	char * secure;
	unsigned int count = 0;


	struct capabilityheader *f = NULL;
	struct capability *temp = NULL;
	struct capability *temp2 = NULL;

	struct analyze *b = NULL;

	iph = ip_hdr(skb);

	middlebox_networkip = ip_str_to_num(middlebox_ip);
	redirect_networkip = ip_str_to_num(redirect_ip);

	if(iph->protocol == IPPROTO_TCP)
	{
		tcph = (struct tcphdr *)((__u32 *)iph+ iph->ihl);		

		tcplen = skb->len - ip_hdrlen(skb);

		if(iph->saddr == redirect_networkip && ntohs(tcph->source) == 9877 && tcph->ack)
		{			
			//printk(KERN_INFO "1#tail room:%u skb_len:%u\n", skb->end - skb->tail, skb->len);
			//printk(KERN_INFO "ADD===>Before:len:%0x tailroom:%0x head:%0x data:%0x tail:%0x end:%0x data_len:%0x\n", skb->len,skb->end-skb->tail, skb->head,skb->data, skb->tail, skb->end, skb->data_len);

			spin_lock(&mylock);
			
			f = searchcapabilityheader(iph->daddr);
			if(f != NULL){

				while((f->first != NULL) && (skb->end - skb->tail) >= capability_len && count < 0xf){		
					temp = f->first;
					secure = skb_put(skb, capability_len);

					b = (struct analyze *)temp->code;					
					printk(KERN_INFO "add id:%u code:%s in ACK <%u>\n", b->id, b->code, count);					
					memcpy(secure, temp->code, capability_len);
					temp2 = temp;
					temp = temp->next;
					kfree(temp2);
					f->first = temp;
					if(f->first == NULL) f->end = NULL;
					count++;
				}			
			
			}
			//printk(KERN_INFO "count:%u\n", count);
			tcph->res1 = count;
			
			spin_unlock(&mylock);
			//printk(KERN_INFO "2#tail room:%u skb_len:%u\n", skb->end - skb->tail, skb->len);
			//printk(KERN_INFO "ADD===>After:len:%0x tailroom:%0x head:%0x data:%0x tail:%0x end:%0x data_len:%0x\n", skb->len,skb->end-skb->tail, skb->head,skb->data, skb->tail, skb->end, skb->data_len);

			iph->tot_len = iph->tot_len + htons(capability_len * count);
			tcplen = skb->len - ip_hdrlen(skb);
			tcph->check = 0; 
			//tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial(tcph, tcph->doff << 2, skb->csum));
			tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial(tcph, tcplen, 0));

			skb->ip_summed = CHECKSUM_NONE;
			ip_send_check(iph);
		}
		
	
 	}
	
//	printk(KERN_INFO "%lu\n", jiffies);                                             //log to var/log/syslog
	return NF_ACCEPT;                                                              
}


/*Called when module loaded using insmod*/
int init_module()
{
	nfho.hook = hook_func;                   
	nfho.hooknum = NF_INET_PRE_ROUTING;   
//	nfho.hooknum = 1;      
	nfho.pf = PF_INET;                           
	nfho.priority = NF_IP_PRI_FIRST;             
	nf_register_hook(&nfho); 
	
	nfho2.hook = hook_func2;
	nfho2.hooknum = NF_INET_POST_ROUTING;
	nfho2.pf = PF_INET;
	nfho2.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfho2);                    
	
	return 0;                                    
}


/*Called when module unloaded using rmmod*/
void cleanup_module()
{
  	nf_unregister_hook(&nfho);   
	nf_unregister_hook(&nfho2);                
}



MODULE_LICENSE("GPL");
MODULE_AUTHOR("HaoJIN");
MODULE_VERSION("1.0");
MODULE_DESCRIPTION("middlepolice");
