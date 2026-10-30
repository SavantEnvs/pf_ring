/* Known-answer test for the vendored libpcap: write a pcap, read it back, run BPF filters over it. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>

static const unsigned char p1[54] = {
  0xff,0xff,0xff,0xff,0xff,0xff, 0x00,0x11,0x22,0x33,0x44,0x55, 0x08,0x00,
  0x45,0x00,0x00,0x28,0x00,0x01,0x00,0x00,0x40,0x06,0x00,0x00, 10,0,0,1, 10,0,0,2,
  0x30,0x39,0x00,0x50,0,0,0,1,0,0,0,0,0x50,0x02,0x20,0x00,0,0,0,0 };
static const unsigned char p2[46] = {
  0xaa,0xbb,0xcc,0xdd,0xee,0xff, 0x00,0x11,0x22,0x33,0x44,0x55, 0x08,0x00,
  0x45,0x00,0x00,0x20,0x00,0x01,0x00,0x00,0x40,0x11,0x00,0x00, 10,0,0,3, 10,0,0,4,
  0x13,0x88,0x00,0x35,0x00,0x0c,0x00,0x00, 'a','b','c','d' };
static const unsigned char p3[42] = {
  0xff,0xff,0xff,0xff,0xff,0xff, 0x00,0x11,0x22,0x33,0x44,0x55, 0x08,0x06,
  0,1, 8,0, 6,4, 0,1, 0x00,0x11,0x22,0x33,0x44,0x55, 10,0,0,1, 0,0,0,0,0,0, 10,0,0,2 };

static const struct { const unsigned char *d; unsigned len; } pk[3] = { {p1,54}, {p2,46}, {p3,42} };

static const char *filters[] = {
  "tcp port 80", "tcp port 8080", "udp", "udp and dst port 53", "ip", "arp",
  "ether broadcast", "ip src 10.0.0.3", "host 10.0.0.2", "len > 50", "less 45",
  "ip[9] = 17", "net 10.0.0.0/30 and not arp", "ether src 00:11:22:33:44:55", "tcp[tcpflags] & tcp-syn != 0",
};

int main(int argc, char **argv)
{
  const char *path = argc > 1 ? argv[1] : "selftest.pcap";
  char err[PCAP_ERRBUF_SIZE];
  pcap_t *dead = pcap_open_dead(DLT_EN10MB, 65535);
  pcap_dumper_t *d = pcap_dump_open(dead, path);
  if (!d) { printf("write=failed\n"); return 1; }
  for (int i = 0; i < 3; i++) {
    struct pcap_pkthdr h = { { 1000 + i, 0 }, pk[i].len, pk[i].len };
    pcap_dump((u_char *)d, &h, pk[i].d);
  }
  pcap_dump_close(d);

  pcap_t *p = pcap_open_offline(path, err);
  if (!p) { printf("read=failed\n"); return 1; }
  printf("linktype=%d snaplen=%d\n", pcap_datalink(p), pcap_snapshot(p));
  struct pcap_pkthdr *h; const u_char *data; int n = 0; unsigned total = 0;
  while (pcap_next_ex(p, &h, &data) > 0) {
    if (memcmp(data, pk[n].d, pk[n].len) != 0) printf("payload%d=mismatch\n", n);
    printf("pkt%d len=%u ts=%ld\n", n, h->caplen, (long)h->ts.tv_sec);
    total += h->caplen; n++;
  }
  printf("packets=%d bytes=%u\n", n, total);
  pcap_close(p);

  for (unsigned f = 0; f < sizeof filters / sizeof *filters; f++) {
    struct bpf_program prog;
    if (pcap_compile(dead, &prog, filters[f], 1, PCAP_NETMASK_UNKNOWN) != 0) { printf("filter[%s]=compile-error\n", filters[f]); continue; }
    int m = 0;
    for (int i = 0; i < 3; i++) {
      struct pcap_pkthdr hh = { { 0, 0 }, pk[i].len, pk[i].len };
      m += pcap_offline_filter(&prog, &hh, pk[i].d) != 0;
    }
    printf("filter[%s]=%d\n", filters[f], m);
    pcap_freecode(&prog);
  }
  struct bpf_program bad;
  printf("badfilter=%d\n", pcap_compile(dead, &bad, "tcp port port (", 1, PCAP_NETMASK_UNKNOWN));
  pcap_close(dead);
  return 0;
}
