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

struct ctableitem{
		unsigned int saddr;
		unsigned int id;
		char code[36];

};

struct ctable{
	struct ctableitem item[10];  	/*ctable contains 10 items*/
	unsigned int n;					/*have inserted capabilities */
	unsigned long start;			/* begin to time*/
	unsigned long stop;				/*stop timing*/
	unsigned int m;					/*have received capabilities*/
};


struct iTable{
	unsigned int f; 	/*f records clients Source ip address */
	unsigned long TA; 	/*TA records the start time of current detection period*/
	unsigned int PID; 	/*The number that has inserted capability.That is one ingredients for computing capabilities.*/
	unsigned long NR; 	/*stores the number of received packets from client*/
	unsigned int ND;	/*the number of dropped by MiddlePolice due to its rate limiting decisions rather than congestions.*/
	unsigned int WR;	/*maximum number of privileged packets allowed for client*/
	char WV[32];		/*designed to learn remote packet losses*/
	unsigned long LR;	/*historical LLR for source*/
	unsigned int i;		/*received capability number*/
	struct iTable *next;
};

struct capability{
	unsigned int num;
	char code[36];

};


unsigned int sendperiod = 750;  //three seconds interval
unsigned int interval = 1000;

struct iTable *iTable_header = NULL;
struct iTable *iTable_tail = NULL;
unsigned int capability_sum = 127;

struct ctable c;
struct ctable *ctab = &c;
unsigned int loadctable = 0;


void initialctable(struct ctable *p){
	p->n = 0;
	p->start = 0;
	p->stop = 0;
	p->m = 0;

}


unsigned int insertctable(struct ctable *p, unsigned int saddr, unsigned int id, char * code){
			unsigned int j = p->n;
			if(j <= 9){
				p->item[j].saddr = saddr;
				p->item[j].id = id;
				memcpy(p->item[j].code, code, 36);
				(p->n)++;
				printk(KERN_INFO "Ctab insert %u capabilities in Ctab <NO. %u>\n", id, p->n);
				return p->n;
				
			}else{
				return 0;
			}
}



void beginToTime(struct ctable *p){
		p->start = jiffies;
		p->stop = jiffies + 250;

}


unsigned int CtableContainCapability(struct ctable *p, unsigned int saddr, unsigned int id, char * code){
		unsigned int i = 0;
		while(i < p->n ){
				if( (p->item[i].saddr == saddr) && (p->item[i].id == id)){
					break;
				}
				i++;

		}		
		if(i < p->n) {

			return 1;
			
		}else {

			return 0;
		}
}


void checkgetcapability(struct ctable *p, unsigned int saddr, unsigned int id, char * code){
	
		if(jiffies <= p->stop){

			if (CtableContainCapability(p, saddr, id, code)){
				(p->m)++;
				printk(KERN_INFO "Ctab check id %u capabilities <Total checked %u>\n", id, p->m);				
			}

		}else{

			/*calculate the drop rate*/
			if(loadctable != 0 && p->n == 10){
				printk(KERN_INFO "Ctable###send %u capabilities receive %u capabilities in one second period.\n", p->n, p->m);
				loadctable = 0;			
			}

		}

}




struct iTable *searchiTable( unsigned int addr){
	
	struct iTable * t = iTable_header;
	while((t != NULL) && (t->f != addr)){
		t = t->next;
	}

	return t;

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
	unsigned char *secure;
	//unsigned char encryptioncode[40] = {'1', 'E','E','E', 'E','E','E','E','E','E','E','E','E','E','E','E','E','E','E','E','E','E','E','E','E','E','E','E','E','E','E','E','E','E','E','E','E','E','E'};
	char encryptioncode[36] = "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE";
	char room[40];
	struct capability *cap = room;  

	struct iTable *temp = NULL;
	
	unsigned int count;	

	iph = ip_hdr(skb);

	middlebox_networkip = ip_str_to_num(middlebox_ip);
	redirect_networkip = ip_str_to_num(redirect_ip);
	
	if(iph->protocol == IPPROTO_TCP)
	{
		tcph = (struct tcphdr *)((__u32 *)iph+ iph->ihl);
		
		tcplen = skb->len - ip_hdrlen(skb);
	
		if(iph->daddr == middlebox_networkip && ntohs(tcph->dest) == 9877 && !tcph->fin)
		{
		//	printk(KERN_INFO "tcph->psh:%0x\n", tcph->psh);
		
			//iph->daddr = redirect_networkip;

			/*add extra 40 bytes in tcp payload*/
			//printk(KERN_INFO "1#tail room:%u skb_len:%u\n", skb->end - skb->tail, skb->len);
			spin_lock(&mylock);
			if(loadctable == 0){

				initialctable(ctab);
				loadctable = 1;
			}
			spin_unlock(&mylock);
			temp = searchiTable(iph->saddr);
			//printk(KERN_INFO "temp point is %x\n", temp);
				
			if (temp == NULL){
				if ((temp = kmalloc(sizeof(struct iTable), GFP_KERNEL)) != NULL){
					printk(KERN_INFO "kmalloc and create one new iTable for one new client\n");
					temp->f = iph->saddr;
					temp->TA = jiffies;
					temp->PID = 0;
					temp->NR = 0;
					temp->ND = 0;
					temp->WR = 0;				
					memset(temp->WV, 0, 32);
					temp->LR = 0;				
					temp->next = NULL;
				}else{
					printk(KERN_INFO "kmalloc failed\n");		
				}
			
				if (iTable_header == NULL){
			 		iTable_header = temp;
			 		iTable_tail = temp;
			 
				}else{

					iTable_tail->next = temp;
					iTable_tail = temp;
				}

			}
			
				
			if ((jiffies - temp->TA) > interval){   		//new interval begin

				//calcuate last interval drop rate and other information
				printk(KERN_INFO "iTable:###Last interval send %u capability get %u capability\n", temp->PID, temp->i);

				//Reset
				temp->TA = jiffies;
				temp->PID = 0;
				temp->NR = 0;
				temp->ND = 0;
				temp->WR = 0;				
				memset(temp->WV, 0, 32);
				temp->LR = 0;	

				temp->i = 0;
				
			} 

			temp->NR++;
			
				
			if(jiffies <= (temp->TA + sendperiod) && temp->PID <= capability_sum){
				//skb->tail = skb->data + skb->len;
				//printk(KERN_INFO "INSERT====>Before:Insert %u capability len:%0x data_len:%u tailroom:%u head:%0x data:%0x tail:%0x end:%0x iplen:%x\n", temp->PID, skb->len, skb->data_len, skb->end-skb->tail, skb->head,skb->data, skb->tail, skb->end, ntohs(iph->tot_len));
				if(skb->end - skb->tail < 40) return NF_ACCEPT;
				tcph->res1 = 0xf;
				//skb->tail = skb->data + skb->len;
				//printk(KERN_INFO "modify tcp res1 to 0xf\n ");
				temp->PID++;
				//memcpy(insertcapability[j], encryptioncode, 40);
				//j++;
				
				secure = skb_put(skb, 40);
				
				cap->num = temp->PID;
				memcpy(cap->code, encryptioncode, 36);
				//printk(KERN_INFO "capability:%s\n", (char *)cap);
				
				memcpy(secure, (char *)cap, 40);
				
				spin_lock(&mylock);
				count = insertctable(ctab, iph->saddr, temp->PID , encryptioncode);

				if(count == 1) beginToTime(ctab);
				spin_unlock(&mylock);

				
				iph->tot_len = iph->tot_len + htons(40);
				//iph->tot_len = skb->len;
				//printk(KERN_INFO "After INSERT===> len:%u data len:%u tailroom:%u head:%0x data:%0x tail:%0x end:%0x iplen:%x\n", skb->len, skb->data_len, skb->end-skb->tail, skb->head, skb->data, skb->tail, skb->end, ntohs(iph->tot_len));
	

				tcplen = skb->len - ip_hdrlen(skb);
				
				tcph->check = 0; 
				//tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial(tcph, tcph->doff << 2, skb->csum));
				tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial(tcph, tcplen, 0));

				skb->ip_summed = CHECKSUM_NONE;
				ip_send_check(iph);

			}
			
		}
 	
	}
	
//	printk(KERN_INFO "%lu\n", jiffies);                                             //log to var/log/syslog
	return NF_ACCEPT;                                                              
}


/*function to be called by hook*/
unsigned int hook_func2(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	char middlebox_ip[15] = "192.168.1.101";
	char redirect_ip[15] = "192.168.1.102";
	struct iphdr *iph = NULL;
	struct tcphdr *tcph=NULL;
	int tcplen;
	unsigned int middlebox_networkip;
	unsigned int redirect_networkip;
	unsigned int res1;
	struct iTable *temp2;
	char getcapability[40];
	struct capability *cap2;

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
			
			temp2 = searchiTable(iph->daddr);
			//printk(KERN_INFO "GETCapability Process===>temp2:%x\n", temp2);			
			
			if((temp2 != NULL) && jiffies <= (temp2->TA + interval) && temp2->i <= capability_sum){
				res1 = tcph->res1;
				//printk(KERN_INFO "GETCAPABILITY===>Before:len:%0x tailroom:%0x head:%0x data:%0x tail:%0x end:%0x data_len:%0x res1:%u\n", skb->len,skb->end-skb->tail, skb->head,skb->data, skb->tail, skb->end, skb->data_len, res1);
				
				while(res1 >= 1){
					//printk(KERN_INFO "print skb->data:%s\n\n", skb->data);
					memcpy(getcapability, (skb->data + skb->len - res1*40), 40);
					//memcpy(id, (skb->data + skb->len - res1*40), 4);
					cap2 = (struct capability *)getcapability;
                			printk(KERN_INFO "get capability id=%u code=%s <res1:%u>\n", cap2->num, cap2->code, res1);				
					spin_lock(&mylock);
					checkgetcapability(ctab, iph->daddr, cap2->num, cap2->code);								  spin_unlock(&mylock);
					
					res1--;
					(temp2->i)++;
					//skb_trim(skb, skb->len - 40);
				}
				
				
				skb_trim(skb, skb->len - tcph->res1*40);
				iph->tot_len = iph->tot_len - htons(tcph->res1*40);
				tcplen = skb->len - ip_hdrlen(skb);
				//printk(KERN_INFO "ip packet length: %d version:%d ttl:%d\n", ntohs(iph->tot_len), iph->version, iph->ttl);
				//printk(KERN_INFO "GETCAPABILITY===>After:len:%0x tailroom:%0x head:%0x data:%0x tail:%0x end:%0x data_len:%0x\n", skb->len,skb->end-skb->tail, skb->head,skb->data, skb->tail, skb->end, skb->data_len);
				tcph->check = 0; 
				//tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial(tcph, tcph->doff << 2, skb->csum));
				tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial(tcph, tcplen, 0));

				skb->ip_summed = CHECKSUM_NONE;
				ip_send_check(iph);
				
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

