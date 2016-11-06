#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <net/tcp.h>
#include <net/ip.h>
#include <linux/spinlock.h>

#define exist_capabilitylist_num 0
#define capability_len 60

char middlebox_ip[15] = "10.20.101.3";
char redirect_ip[15] = "10.20.101.252";
unsigned int middlebox_networkip = 0;
unsigned int redirect_networkip = 0;

static spinlock_t mylock;

static struct nf_hook_ops nfho;
static struct nf_hook_ops nfho2;

struct capability{
	unsigned int num;    	/*num record the number of capability less than capability_sum*/
	unsigned int saddr;		/*saddr record the source address*/ 	
	unsigned long timestamp;	/*timestamp record the arrival time in middlebox*/
	char code[capability_len - 16];

};

struct capability_list{
	char code[capability_len];
	struct capability_list * next;
};


struct capability_header{
        unsigned int saddr;
        struct capability_list *first;  
		struct capability_list *end;
		struct capability_header *next;

};


struct capability_header * header = NULL;
struct capability_header * tail = NULL;



struct capability_header *searchcapabilityheader(unsigned int addr){

	struct capability_header *q = header;
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


unsigned int insertcapabilitylist(unsigned int srcaddr){

			struct capability_header *h = NULL;

			if ((h = kmalloc(sizeof(struct capability_header), GFP_KERNEL)) != NULL){
					printk(KERN_INFO "insertcapabilitylist===>malloc and create capability header:%u\n", srcaddr);
					h->saddr = srcaddr;
					h->first = NULL;
					h->end = NULL;
					h->next = NULL;
					
				}else{
					printk(KERN_INFO "malloc capabilitylist failed.\n");
					return 0;
				}

				if(header == NULL){
					header = h;
					tail = h;
			
				}else{

					tail->next = h;
					tail = h;

				}
				return 1;

}



/*function to be called by hook*/
unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{

	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	int tcplen;

	struct capability_list *p = NULL;
	struct capability_header *h = NULL;

	struct capability *cap = NULL;
	
	iph = ip_hdr(skb);

	if(middlebox_networkip == 0) {
		middlebox_networkip = ip_str_to_num(middlebox_ip);
	}

	if(redirect_networkip == 0){
		redirect_networkip = ip_str_to_num(redirect_ip);
	}


    if(iph->protocol == IPPROTO_TCP)
	{
		tcph = (struct tcphdr *)((__u32 *)iph+ iph->ihl);	
		tcplen = skb->len - ip_hdrlen(skb);

		if(iph->daddr == redirect_networkip && ntohs(tcph->dest) == 9877 && tcph->res1 == 0xf)
		{
			
			//printk(KERN_INFO "TRIM===>Before:len:%0x tailroom:%0x head:%0x data:%0x tail:%0x end:%0x data_len:%0x\n", skb->len,skb->end-skb->tail, skb->head,skb->data, skb->tail, skb->end, skb->data_len);
			
			spin_lock_irq(&mylock);

			h = searchcapabilityheader(iph->saddr);
			if (h == NULL){
				if ((h = kmalloc(sizeof(struct capability_header), GFP_KERNEL)) != NULL){
					//printk(KERN_INFO "malloc and create capability header.\n");
					h->saddr = iph->saddr;
					h->first = NULL;
					h->end = NULL;
					h->next = NULL;
					
				}else{
					printk(KERN_INFO "malloc capability_header fail.\n");
				}

				if(header == NULL){
					header = h;
					tail = h;
			
				}else{

					tail->next = h;
					tail = h;

				}
			}

			
			if ((p = kmalloc(sizeof(struct capability_list), GFP_KERNEL)) != NULL){
				memcpy(p->code, (skb->data + skb->len - capability_len), capability_len);
				
				cap = (struct capability *)p->code;
				//printk(KERN_INFO "skb->len:%u skb->data_len:%u tailroom:%u kmalloc and copy into cap->num:%u cap->saddr:%u cap->timestamp:%lu cap->code:%s\n", skb->len, skb->data_len, skb->end - skb->tail, cap->num, cap->saddr, cap->timestamp, cap->code);

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

			skb_trim(skb, skb->len - capability_len);
			//printk(KERN_INFO "TRIM===>After: len:%u tailroom:%0x head:%0x data:%0x tail:%0x end:%0x\n", skb->len, skb->end-skb->tail, skb->head,skb->data, skb->tail, skb->end);
			spin_unlock_irq(&mylock);			

			iph->tot_len = iph->tot_len - htons(capability_len);
			tcplen = skb->len - ip_hdrlen(skb);
			tcph->check = 0; 
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
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	int tcplen;
	char * secure;
	unsigned int count = 0;


	struct capability_header *f = NULL;
	struct capability_list *temp = NULL;
	struct capability_list *temp2 = NULL;

	struct capability *cap = NULL;

	iph = ip_hdr(skb);

	if(middlebox_networkip == 0) {
		middlebox_networkip = ip_str_to_num(middlebox_ip);
	}

	if(redirect_networkip == 0){
		redirect_networkip = ip_str_to_num(redirect_ip);
	}


	if(iph->protocol == IPPROTO_TCP)
	{
		tcph = (struct tcphdr *)((__u32 *)iph+ iph->ihl);		

		tcplen = skb->len - ip_hdrlen(skb);

		if(iph->saddr == redirect_networkip && ntohs(tcph->source) == 9877 && tcph->ack)
		{			
			//printk(KERN_INFO "ADD===>Before:len:%0x tailroom:%0x head:%0x data:%0x tail:%0x end:%0x data_len:%0x\n", skb->len,skb->end-skb->tail, skb->head,skb->data, skb->tail, skb->end, skb->data_len);

			spin_lock_irq(&mylock);
			
			f = searchcapabilityheader(iph->daddr);
			if(f != NULL){

				while((f->first != NULL) && (skb->end - skb->tail) >= capability_len && count < 0x03){		
					temp = f->first;
					secure = skb_put(skb, capability_len);

					cap = (struct capability *)temp->code;					
					//printk(KERN_INFO "skb->len:%u skb->data_len:%u add num:%u saddr:%u timestamp:%lu code:%s in ACK <%u>\n", skb->len, skb->data_len, cap->num, cap->saddr, cap->timestamp, cap->code, count);					
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
			
			spin_unlock_irq(&mylock);
			//printk(KERN_INFO "ADD===>After:len:%0x tailroom:%0x head:%0x data:%0x tail:%0x end:%0x data_len:%0x\n", skb->len,skb->end-skb->tail, skb->head,skb->data, skb->tail, skb->end, skb->data_len);

			iph->tot_len = iph->tot_len + htons(capability_len * count);
			tcplen = skb->len - ip_hdrlen(skb);
			tcph->check = 0; 
			tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial(tcph, tcplen, 0));
			skb->ip_summed = CHECKSUM_NONE;
			ip_send_check(iph);
		}
		
	
 	}
	
	return NF_ACCEPT;                                                              
}


/*Called when module loaded using insmod*/
int init_module()
{
	unsigned int i = 0;
	unsigned int f = 1;

	while(i < exist_capabilitylist_num){
		
		insertcapabilitylist(f);
		f++;
		i++;
	}

	spin_lock_init(&mylock);	
	nfho.hook = hook_func;                   
	nfho.hooknum = NF_INET_PRE_ROUTING;   
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

