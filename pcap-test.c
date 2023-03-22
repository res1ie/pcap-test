#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);
        if(*(uint16_t*)(packet+0xc)!=0x8)continue;
        if(packet[0x17]!=0x6)continue;
        printf("src mac %02x:%02x:%02x:%02x:%02x:%02x\n",packet[6],packet[7],packet[8],packet[9],packet[10],packet[11]);
        printf("dst mac %02x:%02x:%02x:%02x:%02x:%02x\n",packet[0],packet[1],packet[2],packet[3],packet[4],packet[5]);
        printf("src ip %u.%u.%u.%u\n",packet[26],packet[27],packet[28],packet[29]);
        printf("dst ip %u.%u.%u.%u\n",packet[30],packet[31],packet[32],packet[33]);
        int plen=header->caplen-0x42;
        if(plen<=0)plen=0;
        if(plen>10)plen=10;
        if(plen)
        {
            printf("data ");
            for(int i=0;i<plen;i++)
            {
                printf("%02x",packet[0x42+i]);
            }
        }
        printf("\n\n");
	}

	pcap_close(pcap);
}