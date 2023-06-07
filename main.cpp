#include <pcap.h>
#include <iostream>
#include <map>
#include "mac.h"


using namespace std;


#pragma pack(push, 1)
struct ieee80211_radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
};
#pragma pack(pop)


#pragma pack(push, 1)
struct beacon_frame{
    	u_int16_t type;
    	u_int16_t duration;
   	Mac dest;
    	Mac src;
    	Mac bssid;
    	u_int16_t seq;

    	u_int64_t timestamp; /* fixed parameters */
    	u_int16_t beacon_interval;
    	u_int16_t capa_info;

    	u_int8_t tag_num; /* tag parameters */
    	u_int8_t len;
    	char essid[50];
};
#pragma pack(pop)


typedef struct {
  	int num;
  	string essid;
}beacon_info;

map<string, beacon_info> prt;



void usage() {
  	printf("syntax : airodump <interface>\n");
  	printf("sample : airodump mon0\n");
}


int main(int argc, char** argv){
	if (argc != 2) {
		usage();
		return -1;
	}


	char errbuf[PCAP_ERRBUF_SIZE];
    	pcap_t *handle = pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);
    	if (handle == nullptr) {
        	fprintf(stderr, "couldn't open device %s(%s)\n", argv[1], errbuf);
        	return -1;
    	}
   	struct pcap_pkthdr *header;
    	const u_char *Packet;

  	while (true) {
    		int res = pcap_next_ex(handle, &header, &Packet);
    		if (res == 0) continue;
    		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
     	 		printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
      			break;
    		}

    		ieee80211_radiotap_header *rth = (struct ieee80211_radiotap_header *)Packet;
    		Packet += rth->it_len;
		beacon_frame *bf = (struct beacon_frame*)(Packet);
    		
		if (bf->type == 0x80) {
			string bssid = string(bf->bssid);
         	        string essid = string(bf->essid, bf->len);
                	if (prt.count(bssid)) {
                        	prt[bssid].num++;
                	}
                	else {
                        	prt.insert({bssid, {1, essid}});
               	 	}

			printf("BSSID\t\t\tBeacons\t\tESSID\n");
        		for (auto i:prt) {
                		printf("%s\t%d\t\t%s\n", string(i.first).c_str(), i.second.num, i.second.essid.c_str());
        		}
        		printf("\n");

		}
  	}
  	pcap_close(handle);

}



