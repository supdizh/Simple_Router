/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include <string.h>

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);
  
  printf("*** -> Received packet of length %d \n",len);
  int  minlength = sizeof(sr_ethernet_hdr_t);
  if (len < minlength) {
    fprintf(stderr, "Failed to load ETHERNET header, insufficient length\n");
    return;
  }
  
  uint16_t ethtype = ethertype(packet);
  /*sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t*)(packet);*/
  
  if(ethertype_ip == ethtype){
  	printf("get a ip packet\n");
  	/*i'll use a different style of early return here,don't like too much indent*/
  	minlength += sizeof(sr_ip_hdr_t);
  	if(len < minlength){
  		fprintf(stderr,"Failed to load ip header, insufficient length\n");
  		return;
  	}
  	printf("checking validity\n");
  	sr_ip_hdr_t *iphdr = (sr_ip_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));
  	if(iphdr->ip_v!=4||iphdr->ip_hl<5){
  		fprintf(stderr,"packet version/hl wrong\n");
  		return;
  	}
  	uint32_t ip_sum = iphdr->ip_sum;
  	iphdr->ip_sum = 0;
  	uint32_t ip_cksum = cksum(iphdr,iphdr->ip_hl*4);
  	if(ip_cksum!=ip_sum){
  		fprintf(stderr,"packet checksum WRONG\n");
  		return;
  	}
  	iphdr->ip_sum = ip_cksum;
  	printf("	ip checksum OK\n");
  	struct sr_if *to_interface = sr_get_interface_by_ip(sr,iphdr->ip_dst);
  	if(to_interface){
  		printf("	it's an IP for me\n");
  		if(iphdr->ip_p==1){
  			printf("	it's an ICMP\n");
  			sr_icmp_hdr_t *icmp_hdr =(sr_icmp_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t)
  															+sizeof(sr_ip_hdr_t));
  			if(icmp_hdr->icmp_type!=8||icmp_hdr->icmp_code!=0){
  				printf("	not an echo request\n");
  				return;
  			}
  			uint32_t icmp_cksum = icmp_hdr->icmp_sum;
  			icmp_hdr->icmp_sum = 0;
  			if(icmp_cksum!=cksum((uint8_t*)icmp_hdr,ntohs(iphdr->ip_len)-sizeof(sr_ip_hdr_t))){
  				fprintf(stderr,"	icmp cksum wrong \n");
  				return;
  			}
  			sr_icmp_echo_reply(sr,iphdr);
  		}else{
  			sr_icmp_dest_unr(sr,iphdr,3);
  		}
  	}else{
  		printf("	it's not to me,foward it!\n");
  		printf("	TTL = %d\n",iphdr->ip_ttl);
  		if(iphdr->ip_ttl==1){
  			printf("TTL = 0\n");
  			sr_icmp_TLE(sr,iphdr);
  			return;
  		}
  		iphdr->ip_ttl = iphdr->ip_ttl-1;
	  	iphdr->ip_sum = 0;
	  	iphdr->ip_sum = cksum(iphdr,iphdr->ip_hl*4);
		struct sr_rt *tb = sr_LPM(sr,iphdr->ip_dst);
		if(!tb){
			printf("	no match in LPM,net unreachable\n");
			sr_icmp_dest_unr(sr,iphdr,0);
		}else{
			struct sr_if* interface = sr_get_interface(sr,tb->interface);
			sr_nexthop_ip_iface(sr,packet,len,tb->gw.s_addr,interface);
  		}
  	}
  }else if(ethertype_arp == ethtype){
  	printf("get a arp packet\n");
  	minlength += sizeof(sr_arp_hdr_t);
   	if (len < minlength)
		fprintf(stderr, "Failed to load ARP header, insufficient length\n");
    else{
    	printf("checking validaty\n");
    	sr_arp_hdr_t *arphdr = (sr_arp_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));
    	/*printf("ar_hrd = %x\n",ntohs(arphdr->ar_hrd)*/
	/*print_hdr_arp(packet+sizeof(sr_ethernet_hdr_t));*/
    	if(ntohs(arphdr->ar_hrd)==arp_hrd_ethernet&&
    	   ntohs(arphdr->ar_pro)==ethertype_ip&&
    	   arphdr->ar_hln==0x06&&arphdr->ar_pln==0x04){
    		   	if(ntohs(arphdr->ar_op)==arp_op_request){
    		   		uint32_t _ip = arphdr->ar_tip;
    		   		/*assume sr_if store ip in network order*/
    		   		struct sr_if *interface = sr_get_interface_by_ip(sr,_ip);
    		   		printf("getting a arp request\n");
    		   		if(interface){
    		   			printf("found the interface refered\n");
    		   			/* send a ARP reply to the place(proper interface)*/
    		   			sr_arp_reply(sr,interface,arphdr->ar_sha,arphdr->ar_sip);
    		   			
    		   			struct sr_arpreq *req = sr_arpcache_insert(&sr->cache,arphdr->ar_sha,arphdr->ar_sip);
    		   			
    		   			if(req){
    		   				printf("Got a few packets waiting on incoming request arp\n");
    		   				/* send all packets in req and arp_destroy it*/
    		   				struct sr_packet *pkts = req->packets;
    		   				struct sr_if* interface= 0;
    		   				while(pkts){
    		   					interface = sr_get_interface(sr,pkts->iface);
    		   					sr_nexthop_ip_iface(sr,pkts->buf,pkts->len,req->ip,interface);
    		   					pkts = pkts->next;
    		   				}
    		   				sr_arpreq_destroy(&sr->cache,req);
    		   				printf("req quest queue destoried\n");
    		   				
    		   			}				   
    		   		}
    		   	}else if(ntohs(arphdr->ar_op)==arp_op_reply){
    		   		/* verify it's a reply to me */
    		   		struct sr_if *interface = sr_get_interface_by_ip(sr,arphdr->ar_tip);
    		   		if(interface&&
    		   		!strncmp((const char*)interface->addr,(const char*)arphdr->ar_tha,ETHER_ADDR_LEN)){
    		   			struct sr_arpreq *req = sr_arpcache_insert(&sr->cache,arphdr->ar_sha,arphdr->ar_sip);
    	   			if(req){
    		   				printf("Got a few packets waiting on incoming reply arp\n");
    		   				/* send all packets in req and arp_destroy it*/
    		   				struct sr_packet *pkts = req->packets;
    		   				struct sr_if* interface= 0;
    		   				while(pkts){
    		   					interface = sr_get_interface(sr,pkts->iface);
    		   					sr_nexthop_ip_iface(sr,pkts->buf,pkts->len,req->ip,interface);
    		   					pkts = pkts->next;
    		   				}
    		   				sr_arpreq_destroy(&sr->cache,req);
    		   				printf("req quest queue destoried\n");
    		   				
    		   			}
    		   		}   		   	
    		   	}
    	   	
    	}
  	}
  }else{
  	printf("*** -> Neither arp nor ip of typeid %x \n",ethtype);
  }

  /* fill in code here */

}/* end sr_ForwardPacket */

/*send TLE to the dest defined in iphdr*/
void sr_icmp_TLE(struct sr_instance* sr,sr_ip_hdr_t* siphdr){
	printf("sending icmp TLE\n");
	unsigned int len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+
					   sizeof(sr_icmp_t11_hdr_t);
	uint8_t* buf = (uint8_t*)malloc(len);
	
	sr_ethernet_hdr_t* eth_hdr =(sr_ethernet_hdr_t*)(buf);
	eth_hdr->ether_type = htons(ethertype_ip);
	memset(eth_hdr->ether_shost,0x00,6);
	memset(eth_hdr->ether_dhost,0x00,6);
	/*IP part*/
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*)(buf+sizeof(sr_ethernet_hdr_t));
	ip_hdr->ip_hl = 5;
	ip_hdr->ip_v = 4;
	ip_hdr->ip_tos = siphdr->ip_tos;
	ip_hdr->ip_len = htons(len-sizeof(sr_ethernet_hdr_t));
	ip_hdr->ip_id = siphdr->ip_id;
	ip_hdr->ip_off = 0;
	ip_hdr->ip_ttl = 64;
	ip_hdr->ip_p = 1;
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_dst = siphdr->ip_src;
	/*ip_hdr->ip_src on the interface send out*/
	
	struct sr_rt *tb = sr_LPM(sr,ip_hdr->ip_dst);
	/*if I found none it's safe to quit and print error 
	for otherwise I'll be sending myself icmp net unreachable*/
	if(!tb){
		fprintf(stderr,"Destination net unreachable from the router\n");
		free(buf);
		return;
	}
	struct sr_if* interface = sr_get_interface(sr,tb->interface);
	
	ip_hdr->ip_src = interface->ip;
	ip_hdr->ip_sum = cksum(buf+sizeof(sr_ethernet_hdr_t),sizeof(sr_ip_hdr_t));
	
	/*ICMP part*/
	sr_icmp_t11_hdr_t *icmp_hdr = (sr_icmp_t11_hdr_t*)(buf+sizeof(sr_ethernet_hdr_t)
												          +sizeof(sr_ip_hdr_t));
	icmp_hdr->icmp_type = 11;
	icmp_hdr->icmp_code = 0;
	icmp_hdr->icmp_sum  = 0;
	memcpy(icmp_hdr->data,(uint8_t*)siphdr,ICMP_DATA_SIZE);
	icmp_hdr->icmp_sum  = cksum((uint8_t*)icmp_hdr,len-sizeof(sr_ethernet_hdr_t)
													  -sizeof(sr_ip_hdr_t));
													  

	/*careful here,towards the packet to gw not dest*/	
	sr_nexthop_ip_iface(sr,buf,len,tb->gw.s_addr,interface);
	free(buf);
}

void sr_icmp_echo_reply(struct sr_instance* sr,sr_ip_hdr_t* siphdr){
	printf("sending echo_reply\n");
	uint16_t iplen = ntohs(siphdr->ip_len);
	unsigned int len = sizeof(sr_ethernet_hdr_t)+iplen;
	uint8_t* buf = (uint8_t*)malloc(len);
	
	sr_ethernet_hdr_t* eth_hdr =(sr_ethernet_hdr_t*)(buf);
	eth_hdr->ether_type = htons(ethertype_ip);
	memset(eth_hdr->ether_shost,0x00,6);
	memset(eth_hdr->ether_dhost,0x00,6);
	/*IP part*/
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*)(buf+sizeof(sr_ethernet_hdr_t));
	memcpy(ip_hdr,siphdr,iplen);
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_dst = siphdr->ip_src;
	ip_hdr->ip_src = siphdr->ip_dst;
	ip_hdr->ip_sum = cksum(buf+sizeof(sr_ethernet_hdr_t),sizeof(sr_ip_hdr_t));
	
	struct sr_rt *tb = sr_LPM(sr,ip_hdr->ip_dst);
	/*if I found none it's safe to quit and print error 
	for otherwise I'll be sending myself icmp net unreachable*/
	if(!tb){
		fprintf(stderr,"Destination net unreachable from the router\n");
		free(buf);
		return;
	}
	struct sr_if* interface = sr_get_interface(sr,tb->interface);
	
	
	
	/*ICMP part*/
	sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t*)(buf+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
	icmp_hdr->icmp_type = 0;
	icmp_hdr->icmp_code = 0;
	icmp_hdr->icmp_sum  = 0;
	icmp_hdr->icmp_sum  = cksum((uint8_t*)icmp_hdr,iplen-sizeof(sr_ip_hdr_t));
													  
	/*careful here,towards the packet to gw not dest*/	
	sr_nexthop_ip_iface(sr,buf,len,tb->gw.s_addr,interface);
	free(buf);


}
/*send dest unreachable to the dest define in iphdr
  code = 0/net,1/host,3/port*/
void sr_icmp_dest_unr(struct sr_instance* sr,sr_ip_hdr_t* siphdr,uint8_t code){
	if(code==0)printf("sending net unreachable\n");
	else if(code==1)printf("sending host unreachable\n");
	else printf("sending port unreachable\n");
	
	unsigned int len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+
					   sizeof(sr_icmp_t3_hdr_t);
	uint8_t* buf = (uint8_t*)malloc(len);
	
	sr_ethernet_hdr_t* eth_hdr =(sr_ethernet_hdr_t*)(buf);
	eth_hdr->ether_type = htons(ethertype_ip);
	memset(eth_hdr->ether_shost,0x00,6);
	memset(eth_hdr->ether_dhost,0x00,6);
	/*IP part*/
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*)(buf+sizeof(sr_ethernet_hdr_t));
	ip_hdr->ip_hl = 5;
	ip_hdr->ip_v = 4;
	ip_hdr->ip_tos = siphdr->ip_tos;
	ip_hdr->ip_len = htons(len-sizeof(sr_ethernet_hdr_t));
	ip_hdr->ip_id = siphdr->ip_id;
	ip_hdr->ip_off = 0;
	ip_hdr->ip_ttl = 64;
	ip_hdr->ip_p = 1;
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_dst = siphdr->ip_src;
	
	struct sr_rt *tb = sr_LPM(sr,ip_hdr->ip_dst);
	/*if I found none it's safe to quit and print error 
	for otherwise I'll be sending myself icmp net unreachable*/
	if(!tb){
		fprintf(stderr,"Destination net unreachable from the router\n");
		free(buf);
		return;
	}
	struct sr_if* interface = sr_get_interface(sr,tb->interface);
	
	if(code==3)ip_hdr->ip_src = siphdr->ip_dst;
	else ip_hdr->ip_src = interface->ip;
	/*for port unreachable it's towards me,it has to be that specific ip*/
	
	ip_hdr->ip_sum = cksum((uint8_t*)ip_hdr,sizeof(sr_ip_hdr_t));
	
	/*ICMP part*/
	sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t*)((uint8_t*)ip_hdr+sizeof(sr_ip_hdr_t));
	icmp_hdr->icmp_type = 3;
	icmp_hdr->icmp_code = code;
	icmp_hdr->icmp_sum  = 0;
	memcpy(icmp_hdr->data,(uint8_t*)siphdr,ICMP_DATA_SIZE);
	icmp_hdr->icmp_sum  = cksum((uint8_t*)icmp_hdr,len-sizeof(sr_ethernet_hdr_t)
													  -sizeof(sr_ip_hdr_t));
													  

	/*careful here,towards the packet to gw not dest*/	
	sr_nexthop_ip_iface(sr,buf,len,tb->gw.s_addr,interface);
	free(buf);
}



void sr_nexthop_ip_iface(struct sr_instance* sr,uint8_t* packet,unsigned int len,uint32_t tip,struct sr_if* interface){
/*remember! ethernet_dhost still blank!*/
	assert(sr);
	assert(packet);
	assert(interface);
	
	struct sr_arpentry* arp = sr_arpcache_lookup(&sr->cache,tip);
	if(!arp){
		/*arp entry not found ,TRY ARP REQUEST*/
		printf("arp entry not found,try request");
		sr_arpcache_queuereq(&sr->cache,tip,packet,len,interface->name);
	}else{
		sr_ethernet_hdr_t* eth_hdr =(sr_ethernet_hdr_t*)(packet);
		memcpy(eth_hdr->ether_dhost,arp->mac,6);
		memcpy(eth_hdr->ether_shost,interface->addr,6);
		sr_send_packet(sr,packet,len,interface->name);
		free(arp);
	}
}
