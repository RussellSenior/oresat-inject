/**
 * Hello, and welcome to this brief, but hopefully complete, example file for
 * wireless packet injection using pcap.
 *
 * Although there are various resources for this spread on the web, it is hard
 * to find a single, cohesive piece that shows how everything fits together.
 * This file aims to give such an example, constructing a fully valid UDP packet
 * all the way from the 802.11 PHY header (through radiotap) to the data part of
 * the packet and then injecting it on a wireless interface
 *
 * Skip down a couple of lines, as the following is just headers and such that
 * we need.
 */
#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <argp.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>

/* Defined in include/linux/ieee80211.h */
struct ieee80211_hdr {
  uint16_t /*__le16*/ frame_control;
  uint16_t /*__le16*/ duration_id;
  uint8_t addr1[6];
  uint8_t addr2[6];
  uint8_t addr3[6];
  uint16_t /*__le16*/ seq_ctrl;
  //uint8_t addr4[6];
} __attribute__ ((packed));

#define WLAN_FC_TYPE_DATA	2
#define WLAN_FC_SUBTYPE_DATA	0


/*************************** START READING AGAIN ******************************/

/**
 * Radiotap is a protocol of sorts that is used to convey information about the
 * physical-layer part of wireless transmissions. When monitoring an interface
 * for packets, it will contain information such as what rate was used, what
 * channel it was sent on, etc. When injecting a packet, we can use it to tell
 * the 802.11 card how we want the frame to be transmitted.
 *
 * The format of the radiotap header is somewhat odd.
 * include/net/ieee80211_radiotap.h does an okay job of explaining it, but I'll
 * try to give a quick overview here.
 *
 * Keep in mind that all the fields here are little-endian, so you should
 * reverse the order of the bytes in your head when reading. Also, fields that
 * are set to 0 just mean that we let the card choose what values to use for
 * that option (for rate and channel for example, we'll let the card decide).
 */
static const uint8_t u8aRadiotapHeader[] = {
  0x00, 0x00, 0x0C, 0x00, 0x06, 0x80, 0x00, 0x00, 0x10, 0x0c, 0x08, 0x00 // from Scapy
//  0x00, 0x00, 0x0C, 0x00, 0x06, 0x80, 0x00, 0x00, 0x10, 0x02, 0x08, 0x00 // from Scapy
};

/**
 * After an 802.11 MAC-layer header, a logical link control (LLC) header should
 * be placed to tell the receiver what kind of data will follow (see IEEE 802.2
 * for more information).
 *
 * For political reasons, IP wasn't allocated a global so-called SAP number,
 * which means that a simple LLC header is not enough to indicate that an IP
 * frame was sent. 802.2 does, however, allow EtherType types (the same kind of
 * type numbers used in, you guessed it, Ethernet) through the use of the
 * "Subnetwork Access Protocol", or SNAP. To use SNAP, the three bytes in the
 * LLC have to be set to the magical numbers 0xAA 0xAA 0x03. The next five bytes
 * are then interpreted as a SNAP header. To specify an EtherType, we need to
 * set the first three of them to 0. The last two bytes can then finally be set
 * to 0x0800, which is the IP EtherType.
 */
const uint8_t ipllc[6] = { 0x00, 0x00, 0x03, 0x00, 0x00, 0x00 };

/* The parts of our packet */
uint8_t *rt; /* radiotap */
struct ieee80211_hdr *hdr;
uint8_t *llc;
uint8_t *data;

/* Other useful bits */
uint8_t *buf;
size_t sz;
uint8_t fcchunk[2]; /* 802.11 header frame control */

uint8_t p[1500+sizeof(u8aRadiotapHeader)];

const char *argp_program_version = "inject 0.1";
const char *argp_program_bug_address = "inject-bugs@klickitat.com";

static char doc[] =
  "inject takes an input file, chops it into blocksize chunks and injects them\v\
into a monitor mode wifi interface.";

int verbose = 0;
int version = 0;
uint32_t delay = 0;
char const *iface = "mon0";
int n = 1;
int k = 1;
int blocksize = 1400;
uint8_t *sender;
uint8_t mac[6] = { 0x05, 0x03, 0x05, 0x03, 0x05, 0x03 };
int pass = 1;
int transmission = 1;
int eot = 3;

struct arguments {
  unsigned n;
  char **argz;
};

static int
parse_opt (int key, char *arg, struct argp_state *state)
{
  struct arguments *a = (struct arguments *) state->input;
  switch (key)
    {

    case 'i':
      iface = arg;
      break;

    case 'n':
      n = atoi(arg);
      break;

    case 'k':
      k = atoi(arg);
      break;

    case 'd':
      delay = atoi(arg);
      break;

    case 'b':
      blocksize = atoi(arg);
      break;

    case 's':
      sender = arg;
      int rc = sscanf(sender, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		      mac, mac + 1, mac + 2, mac + 3, mac + 4, mac + 5);
      if (rc != 6) {
	fprintf(stderr,"Error: invalid macaddr: %s\n",arg);
	exit(-1);
      }
      break;

    case 'p':
      pass = atoi(arg);
      break;

    case 't':
      transmission = atoi(arg);
      break;

    case 'e':
      eot = atoi(arg);
      break;

    case 'v':
      verbose++;
      break;

    case 'V':
      version = 1;
      break;

    case ARGP_KEY_INIT:
      a->n = 0;
      a->argz[a->n] = NULL;
      break;

    case ARGP_KEY_ARG:
      a->argz[a->n] = strdup(arg);
      a->n++;
      a->argz[a->n] = NULL;
      break;
    }
  return 0;
}

int hexdump(uint8_t *ptr,int size) {
  int i=0;

  while (i<size) {
    printf("%08x",i);
    for(int j=0 ; j<16 && i<size ; i++,j++) {
      printf(" %02x",*(ptr+i));
    }
    printf("\n");
  }
  return 0;
}

int sendfile(pcap_t *ppcap,int fd) {
  int in; // bytes read
  uint32_t frame = 0;
  uint16_t r[3];

  hdr->addr1[0] = pass & 0xff;
  hdr->addr1[1] = transmission & 0xff;
  r[0] = htons((uint16_t) n);
  r[1] = htons((uint16_t) k);
  r[2] = 0;
  memcpy(&hdr->addr3[0],(uint8_t *) r,6);

  while((in = read(fd,data,blocksize)) > 0) {
    uint32_t q = htonl(frame);
    memcpy(&hdr->addr1[2],((uint8_t *) &q),4);
    if(verbose > 2) hexdump(p,sz+in);
    if (pcap_sendpacket(ppcap, p, sz + in) != 0) {    
      /**
       * If something went wrong, let's let our user know
       */
      pcap_perror(ppcap, "Failed to inject packet");
      return 1;
    }
    if (delay) {
      usleep(delay);
    }
    if (verbose) {
      printf("frame %d (%ld bytes)\n",frame,sz+in);
    }
    frame++;
  }

  memset(&hdr->addr3[0],0xff,6);
  for(int i=0 ; i<eot ; i++) {
    uint32_t q = htonl(frame);
    memcpy(&hdr->addr1[2],((uint8_t *) &q),4);
    memset(data,0xff,4); // clear any FCS
    if(verbose > 2) hexdump(p,sz);
    if (pcap_sendpacket(ppcap, p, sz) != 0) {
      /**
       * If something went wrong, let's let our user know
       */
      pcap_perror(ppcap, "Failed to inject packet");
      return 1;
    }
    if (delay) {
      usleep(delay);
    }
    if (verbose) {
      printf("eot frame %d (%ld bytes)\n",frame,sz);
    }
    frame++;
  }

  return 0;
}

int main(int argc,char** argv)
{
  int c;

  struct argp_option options[] = {
    { "verbose", 'v', 0, 0, "Be more verbose" },
    { "version", 'V', 0, 0, "Version" },
    { "iface", 'i', "<interface>", 0, "Specify the monitor mode interface (default: mon0)" },
    { "delay", 'd', "<delay>", 0, "interpacket delay in microseconds {default: 0)" },
    { 0, 'n', "<n>", 0, "LDPC Staircase n blocks (default: 1)" },
    { 0, 'k', "<k>", 0, "LDPC Staircase k blocks (default: 1)" },
    { "blocksize", 'b', "<blocksize>", 0, "Blocksize in bytes (default: 1400)" },
    { "sender", 's', "<macaddr>", 0, "Sending BSSID (default: 05:03:05:03:05:03)" },
    { "pass", 'p', "<pass>", 0, "Scheduled pass number (default: 1)" },
    { "transmission", 't', "<fileno>", 0, "Image number within pass (default: 1)" },
    { "eot", 'e', "<n>", 0, "Number of EOT packets to send (default: 1)" },
    { 0 }
  };

  struct argp argp = { options, parse_opt, "input file", doc };

  struct arguments arguments;
  arguments.argz = (char **) calloc (argc, sizeof (char *));
  arguments.argz[0] = NULL;
  arguments.n = 0;

  int arg_count = 0;
  if (argp_parse (&argp, argc, argv, 0, 0, &arguments))
    return -1;

  if(verbose) {
    fprintf(stderr,"verbose = %d\n",verbose);
    fprintf(stderr,"version = %d\n",version);
    fprintf(stderr,"iface = %s\n",iface);
    fprintf(stderr,"delay = %u\n",delay);
    fprintf(stderr,"n = %d\n",n);
    fprintf(stderr,"k = %d\n",k);
    fprintf(stderr,"blocksize = %d\n",blocksize);
    fprintf(stderr,"sender = %02x:%02x:%02x:%02x:%02x:%02x\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    fprintf(stderr,"pass = %d\n",pass);
    fprintf(stderr,"transmission = %d\n",transmission);
    fprintf(stderr,"eot = %d\n",eot);
    for (int i=0 ; i<arguments.n ; i++) {
      fprintf(stderr,"argz[%u] = %s\n",i,arguments.argz[i]);
    }

  }

  /* PCAP vars */
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *ppcap;
 
  /* Total buffer size (note the 0 bytes of data and the 4 bytes of FCS */
  sz = sizeof(u8aRadiotapHeader) + sizeof(struct ieee80211_hdr) + sizeof(ipllc) + 0 /* data */ + 4 /* FCS */;

  /* Put our pointers in the right place */
  rt = p;
  hdr = (struct ieee80211_hdr *) (p+sizeof(u8aRadiotapHeader));
  llc = (uint8_t *) (p + sizeof(u8aRadiotapHeader) + sizeof(struct ieee80211_hdr));
  data = (uint8_t *) (llc + sizeof(ipllc));

  /* The radiotap header has been explained already */
  memcpy(rt, u8aRadiotapHeader, sizeof(u8aRadiotapHeader));

  /**
   * Next, we need to construct the 802.11 header
   *
   * The biggest trick here is the frame control field.
   * http://www.wildpackets.com/resources/compendium/wireless_lan/wlan_packets
   * gives a fairly good explanation.
   *
   * The first byte of the FC gives the type and "subtype" of the 802.11 frame.
   * We're transmitting a data frame, so we set both the type and the subtype to
   * DATA.
   *
   * Most guides also forget to mention that the bits *within each byte* in the
   * FC are reversed (!!!), so FROMDS is actually the *second to last* bit in
   * the FC, hence 0x02.
   */
  fcchunk[0] = ((WLAN_FC_TYPE_DATA << 2) | (WLAN_FC_SUBTYPE_DATA << 4));
  fcchunk[1] = 0x02;
  memcpy(&hdr->frame_control, &fcchunk[0], 2*sizeof(uint8_t));

  /**
   * The remaining fields are more straight forward.
   * The duration we can set to some arbitrary high number, and the sequence
   * number can safely be set to 0.
   * The addresses here can be set to whatever, but bear in mind that which
   * address corresponds to source/destination/BSSID will vary depending on
   * which of TODS and FROMDS are set. The full table can be found at the
   * wildpackets.com link above, or condensed here:
   *
   *  +-------+---------+-------------+-------------+-------------+-----------+
   *  | To DS | From DS | Address 1   | Address 2   | Address 3   | Address 4 |
   *  +-------+---------+-------------+-------------+-------------+-----------+
   *  |     0 |       0 | Destination | Source      | BSSID       | N/A       |
   *  |     0 |       1 | Destination | BSSID       | Source      | N/A       |
   *  |     1 |       0 | BSSID       | Source      | Destination | N/A       |
   *  |     1 |       1 | Receiver    | Transmitter | Destination | Source    |
   *  +-------+---------+-------------+-------------+-------------+-----------+
   *
   * Also note that addr4 has been commented out. This is because it should not
   * be present unless both TODS *and* FROMDS has been set (as shown above).
   */
  hdr->duration_id = 0xffff;
  memcpy(&hdr->addr2[0], mac, 6*sizeof(uint8_t));
  hdr->seq_ctrl = 0;
  //hdr->addr4;

  
  /* The LLC+SNAP header has already been explained above */
  memcpy(llc, ipllc, sizeof(ipllc));

  /**
   * Finally, we have the packet and are ready to inject it.
   * First, we open the interface we want to inject on using pcap.
   */
  ppcap = pcap_open_live(iface, 800, 1, 20, errbuf);

  if (ppcap == NULL) {
    printf("Could not open interface wlan0 for packet injection: %s", errbuf);
    return 2;
  }


  int fd;

  // for each filename (special case: no filename = stdin)
  if (arguments.n == 0) {
      fd = fileno(stdin);
      sendfile(ppcap,fd);
      close(fd);
  }
  else {
    for(int i=0 ; i<arguments.n ; i++) {
      fd = open(arguments.argz[i],O_RDONLY);
      sendfile(ppcap,fd);
      close(fd);
    }
  }
  
  pcap_close(ppcap);
  return 0;
}

