#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <net/tcp.h>
#include <net/ip.h>

spinlock_t mylock = __SPIN_LOCK_UNLOCKED(mylock);
static struct nf_hook_ops nfho;

static struct nf_hook_ops nfho2;

char getcapability[64][40];
char insertcapability[64][40];
unsigned int i = 0;
unsigned int j = 0;

unsigned int sendperiod = 750;  //three seconds interval
unsigned int endinterval = 1000; //four seconds
unsigned long start = 0;
unsigned long end = 0; 


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
	unsigned char *secure;
	unsigned char encryptioncode[40] = "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE";

	iph = ip_hdr(skb);

	middlebox_networkip = ip_str_to_num(middlebox_ip);
	//printk(KERN_INFO "middlebox network IP=%u\n", middlebox_networkip);

	redirect_networkip = ip_str_to_num(redirect_ip);
    //printk(KERN_INFO "redirect network IP=%u\n", redirect_networkip);

        if(iph->protocol == IPPROTO_TCP)
	{
		tcph = (struct tcphdr *)((__u32 *)iph+ iph->ihl);
		
		tcplen = skb->len - ip_hdrlen(skb);

		//printk(KERN_INFO "destIP:%u   srcIP:%u    dest port:%u     src port:%u\n", iph->daddr, iph->saddr, tcph->dest, tcph->source); 		
		if(iph->daddr == middlebox_networkip && ntohs(tcph->dest) == 9877)
		{
		//	printk(KERN_INFO "tcph->psh:%0x\n", tcph->psh);
		
			//iph->daddr = redirect_networkip;

			/*add extra 40 bytes in tcp payload*/
			//printk(KERN_INFO "1#tail room:%u skb_len:%u\n", skb->end - skb->tail, skb->len);
			if(start == 0){
				start = jiffies;
				end = jiffies + sendperiod;
			}

			if(jiffies <= end && j <= 64){
				//skb->tail = skb->data + skb->len;
				printk(KERN_INFO "Before:Insert %u capability at %lu <start:%lu end:%lu> len:%0x data_len:%u tailroom:%u head:%0x data:%0x tail:%0x end:%0x\n", j, jiffies, start, end, skb->len, skb->data_len, skb->end-skb->tail, skb->head,skb->data, skb->tail, skb->end);
				tcph->res1 = 0xf;
				//skb->tail = skb->data + skb->len;
				//printk(KERN_INFO "modify tcp res1 to 0xf\n ");	
				memcpy(insertcapability[j], encryptioncode, 40);
				j++;
			
				secure = skb_put(skb, 40);
				memcpy(secure, encryptioncode, 40);
				printk(KERN_INFO "after insert: len:%u data len:%u tailroom:%u head:%0x data:%0x tail:%0x end:%0x\n", skb->len, skb->data_len, skb->end-skb->tail, skb->head, skb->data, skb->tail, skb->end);
				iph->tot_len = iph->tot_len + htons(40);
				//printk(KERN_INFO "2#tail room:%u skb_len:%u\n", skb->end - skb->tail, skb->len);
			

				tcplen = skb->len - ip_hdrlen(skb);

				
				tcph->check = 0; 
				//tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial(tcph, tcph->doff << 2, skb->csum));
				tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial(tcph, tcplen, 0));

				skb->ip_summed = CHECKSUM_NONE;
				ip_send_check(iph);

			}else if(jiffies > endinterval){
				printk(KERN_INFO "Last interval send %u capability get %u capability\n", j, i);
				start = 0;
				j = 0;
				i = 0;
			}
	
		}
 	}
	
//	printk(KERN_INFO "%lu\n", jiffies);                                             //log to var/log/syslog
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
	unsigned int res1;

	iph = ip_hdr(skb);

	middlebox_networkip = ip_str_to_num(middlebox_ip);
	//printk(KERN_INFO "middlebox network IP=%u\n", middlebox_networkip);

	redirect_networkip = ip_str_to_num(redirect_ip);
    //printk(KERN_INFO "redirect network IP=%u\n", redirect_networkip);

    if(iph->protocol == IPPROTO_TCP)
	{
		//printk(KERN_INFO "ip dest IP=%u\n", iph->daddr);
		tcph = (struct tcphdr *)((__u32 *)iph+ iph->ihl);		

		tcplen = skb->len - ip_hdrlen(skb);

		//printk(KERN_INFO "destIP:%u   srcIP:%u    dest port:%u     src port:%u\n", iph->daddr, iph->saddr, tcph->dest, tcph->source); 		
	
		if(iph->saddr == redirect_networkip && ntohs(tcph->source) == 9877 && tcph->ack && (tcph->res1 != 0))
		{
			
			//printk(KERN_INFO "reserve field:%u\n", tcph->res1);
                        if(start == 0){
                                start = jiffies;
                                end = jiffies + sendperiod;
                        }

			if(jiffies <= start + endinterval && i <= 64){
				res1 = tcph->res1;
				while(res1 >= 1){
					memcpy(getcapability[i], (skb->data + skb->len - res1*40), 40);
                			printk(KERN_INFO "get capability=%s at %lu <res1:%u>\n", getcapability[i], jiffies, res1);
					res1--;
					i++;
					//skb_trim(skb, skb->len - 40);
				}

				skb_trim(skb, skb->len - tcph->res1*40);
				iph->tot_len = iph->tot_len - htons(tcph->res1*40);
				tcplen = skb->len - ip_hdrlen(skb);
				//printk(KERN_INFO "ip packet length: %d version:%d ttl:%d\n", ntohs(iph->tot_len), iph->version, iph->ttl);

				tcph->check = 0; 
				//tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial(tcph, tcph->doff << 2, skb->csum));
				tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial(tcph, tcplen, 0));

				skb->ip_summed = CHECKSUM_NONE;
				ip_send_check(iph);
				
			}else if(jiffies > start + endinterval){
				printk(KERN_INFO "Last interval receive %u capability\n", i);
				i = 0;
				j = 0;
				start = 0;
				//calculate the drop rate  {}

			}

			
		}
 	}
	
//	printk(KERN_INFO "%lu\n", jiffies);                                             //log to var/log/syslog
	return NF_ACCEPT;                                                              
}



/*Called when module loaded using insmod*/
int init_module()
{
	nfho.hook = hook_func;                   
	nfho.hooknum = NF_INET_POST_ROUTING;   
//	nfho.hooknum = 1;      
	nfho.pf = PF_INET;                           
	nfho.priority = NF_IP_PRI_FIRST;             
	nf_register_hook(&nfho);  

	nfho2.hook = hook_func2;                   
	nfho2.hooknum = NF_INET_PRE_ROUTING;   
//	nfho2.hooknum = 1;      
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

