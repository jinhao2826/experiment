#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <net/tcp.h>
#include <net/ip.h>

#define ctable_num 10
#define capability_room 60 /*capability room 60 bytes*/
#define mtu 1300

static spinlock_t mylock;

static struct nf_hook_ops nfho;

static struct nf_hook_ops nfho2;

struct capability{
	unsigned int num;    	/*num record the number of capability less than capability_sum*/
	unsigned int saddr;		/*saddr record the source address*/ 	
	unsigned long timestamp;	/*timestamp record the arrival time in middlebox*/
	char code[capability_room - 16];

};


struct ctable{
	struct capability item[ctable_num];  	/*ctable contains 10 items*/
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


unsigned int insertctable(struct ctable *p, unsigned int saddr, unsigned int id, unsigned long time, char * code){
			unsigned int j = p->n;
			if(j <= (ctable_num - 1)){
				p->item[j].saddr = saddr;
				p->item[j].num = id;
				p->item[j].timestamp = time;
				memcpy(p->item[j].code, code, capability_room - 16);
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


unsigned int CtableContainCapability(struct ctable *p, unsigned int id, unsigned int saddr, unsigned long time, char * code){
		unsigned int i = 0;
		while(i < p->n ){
				if( (p->item[i].num == id) && (p->item[i].saddr == saddr) && (p->item[i].timestamp == time)){
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


void checkgetcapability(struct ctable *p, unsigned int id, unsigned int saddr, unsigned long time, char * code){
	
		if(p->n < ctable_num){

			if (CtableContainCapability(p, id, saddr, time, code)){
				(p->m)++;
				printk(KERN_INFO "Ctab check id %u capabilities <Total checked %u>\n", id, p->m);
				if(jiffies > p->stop){

					p->stop = jiffies + 250;}
				}
		}else if(jiffies <= p->stop){

			if (CtableContainCapability(p, id, saddr, time, code)){
				(p->m)++;
				printk(KERN_INFO "Ctab check id %u capabilities <Total checked %u>\n", id, p->m);

			}

		}else{

			/*calculate the drop rate*/
			if(loadctable != 0 && p->n == ctable_num){
				printk(KERN_INFO "Ctable###send %u capabilities receive %u capabilities in this interval.\n", p->n, p->m);
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

	char encryptioncode[36] = "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE";
	char room[capability_room];
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

			spin_lock_irq(&mylock);
			if(loadctable == 0){

				initialctable(ctab);
				loadctable = 1;
			}
			
			temp = searchiTable(iph->saddr);
				
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

				//printk(KERN_INFO "INSERT====>Before:Insert %u capability len:%0x data_len:%u tailroom:%u head:%0x data:%0x tail:%0x end:%0x iplen:%x\n", temp->PID, skb->len, skb->data_len, skb->end-skb->tail, skb->head,skb->data, skb->tail, skb->end, ntohs(iph->tot_len));
				//if((skb->len != mtu)||(skb->end - skb->tail < capability_room)) return NF_ACCEPT;
				if((skb->end - skb->tail < capability_room)) return NF_ACCEPT;
			
				temp->PID++;
				
				cap->num = temp->PID;
				cap->saddr = iph->saddr;
				cap->timestamp = jiffies;
				memcpy(cap->code, encryptioncode, 36);

				secure = skb_put(skb, capability_room);
				memcpy(secure, (char *)cap, capability_room);
				tcph->res1 = 0xf;
				//printk(KERN_INFO "skb->len:%u skb->data_len:%u tailroom:%u kmalloc and copy into cap->num:%u cap->saddr:%u cap->timestamp:%lu cap->code:%s\n", skb->len,skb->data_len, skb->end - skb->tail, cap->num, cap->saddr, cap->timestamp, cap->code);

				
				count = insertctable(ctab, cap->saddr, cap->num, cap->timestamp, cap->code);

				if(count == 1) beginToTime(ctab);
				
				iph->tot_len = iph->tot_len + htons(capability_room);
				//printk(KERN_INFO "After INSERT===> len:%u data len:%u tailroom:%u head:%0x data:%0x tail:%0x end:%0x iplen:%x\n", skb->len, skb->data_len, skb->end-skb->tail, skb->head, skb->data, skb->tail, skb->end, ntohs(iph->tot_len));
	

				tcplen = skb->len - ip_hdrlen(skb);
				
				tcph->check = 0; 
				//tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial(tcph, tcph->doff << 2, skb->csum));
				tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial(tcph, tcplen, 0));

				skb->ip_summed = CHECKSUM_NONE;
				ip_send_check(iph);

			}
			spin_unlock_irq(&mylock);		
				
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
	char getcapability[capability_room];
	struct capability *cap2;

	iph = ip_hdr(skb);

	middlebox_networkip = ip_str_to_num(middlebox_ip);

	redirect_networkip = ip_str_to_num(redirect_ip);

  	if(iph->protocol == IPPROTO_TCP)
	{

		tcph = (struct tcphdr *)((__u32 *)iph+ iph->ihl);		

		tcplen = skb->len - ip_hdrlen(skb);

		//printk(KERN_INFO "destIP:%u   srcIP:%u    dest port:%u     src port:%u\n", iph->daddr, iph->saddr, tcph->dest, tcph->source); 		
	
		if(iph->saddr == redirect_networkip && ntohs(tcph->source) == 9877 && tcph->ack && (tcph->res1 != 0))
		{
			spin_lock_irq(&mylock);	
			temp2 = searchiTable(iph->daddr);
			
			if((temp2 != NULL) && jiffies <= (temp2->TA + interval) && temp2->i <= capability_sum){
				res1 = tcph->res1;
				//printk(KERN_INFO "GETCAPABILITY===>Before:len:%0x tailroom:%0x head:%0x data:%0x tail:%0x end:%0x data_len:%0x res1:%u\n", skb->len,skb->end-skb->tail, skb->head,skb->data, skb->tail, skb->end, skb->data_len, res1);
					
				while(res1 >= 1){

					memcpy(getcapability, (skb->data + skb->len - res1*capability_room), capability_room);
					cap2 = (struct capability *)getcapability;
					printk(KERN_INFO "get capability skb->len:%u skb->data_len:%u num=%u saddr=%u timestamp=%lu code=%s <res1:%u>\n",skb->len, skb->data_len, cap2->num, cap2->saddr, cap2->timestamp, cap2->code, res1);
					
					checkgetcapability(ctab, cap2->num, cap2->saddr, cap2->timestamp, cap2->code);								  
					
					
					res1--;
					(temp2->i)++;

				}
				
				skb_trim(skb, skb->len - tcph->res1 * capability_room);
				iph->tot_len = iph->tot_len - htons(tcph->res1 * capability_room);
				tcplen = skb->len - ip_hdrlen(skb);
				//printk(KERN_INFO "ip packet length: %d version:%d ttl:%d\n", ntohs(iph->tot_len), iph->version, iph->ttl);
				//printk(KERN_INFO "GETCAPABILITY===>After:len:%0x tailroom:%0x head:%0x data:%0x tail:%0x end:%0x data_len:%0x\n", skb->len,skb->end-skb->tail, skb->head,skb->data, skb->tail, skb->end, skb->data_len);
				tcph->check = 0; 
				//tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial(tcph, tcph->doff << 2, skb->csum));
				tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial(tcph, tcplen, 0));

				skb->ip_summed = CHECKSUM_NONE;
				ip_send_check(iph);
				
			}
			spin_unlock_irq(&mylock);
				
		}
 	}
	
//	printk(KERN_INFO "%lu\n", jiffies);                                             //log to var/log/syslog
	return NF_ACCEPT;                                                              
}



/*Called when module loaded using insmod*/
int init_module()
{
	spin_lock_init(&mylock);
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

