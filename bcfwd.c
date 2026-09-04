// bcfwd forwards directed UDP broadcast packets to all other attached networks,
// changing the destination address to the corresponding directed broadcast
// address.  Requires `CAP_NET_RAW` to open a raw UDP socket.

// gcc -o bcfwd bcfwd.c -Wall -Wextra -pedantic -Os -static -DNDEBUG=1 -Wa,--gsframe=no -fomit-frame-pointer -ffunction-sections -fdata-sections -Wl,--gc-sections

#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>

#ifndef NDEBUG
#include <stdio.h>
#endif

#define IPADDR "%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8
#define IPWORD(addr) (uint8_t)((addr) >> 24), (uint8_t)((addr) >> 16), (uint8_t)((addr) >> 8), (uint8_t)((addr) >> 0)
#define IPBYTES(addr) (addr)[0], (addr)[1], (addr)[2], (addr)[3]

struct netw {
  uint32_t nn, bc;
} netwbuf[64];

const struct netw *localNets(void) {
  netwbuf[0].nn = 0x0a070000;
  netwbuf[0].bc = 0x0a07ffff;
  netwbuf[1].nn = 0xa9fe0000;
  netwbuf[1].bc = 0xa9feffff;
  return netwbuf;
}

static inline uint16_t load16(const uint8_t b[static const 2]) {
  return b[0] << 8 | b[1] << 0;
}
static inline void store16(uint8_t b[static const 2], const uint16_t val) {
  b[0] = val >> 8;
  b[1] = val;
}
static inline uint32_t load32(const uint8_t b[static const 4]) {
  return b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3] << 0;
}
static inline void store32(uint8_t b[static const 4], const uint32_t val) {
  b[0] = val >> 24;
  b[1] = val >> 16;
  b[2] = val >> 8;
  b[3] = val >> 0;
}

#ifndef NDEBUG
uint16_t checksum16(const uint8_t *const buf, const size_t sz) {
  uint32_t sum = 0;
  for (size_t i = 0; i + 1 < sz; i += 2) {
    sum += load16(&buf[i]);
  }
  while (sum >> 16) {
    sum = (uint16_t)sum + (sum >> 16);
  }
  return sum;
}
#endif

int main(void) {
  const struct netw *netws = localNets();
#ifndef NDEBUG
  for (const struct netw *netw = netws; netw->nn; ++netw) {
    printf("Local network " IPADDR ", broadcast " IPADDR "\n", IPWORD(netw->nn), IPWORD(netw->bc));
  }
#endif
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
  if (sock == -1) {
#ifndef NDEBUG
    perror("Error opening socket");
#endif
    return 1;
  }
  int iret;
  const int one = 1;
  iret = setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
  if (iret == -1) {
#ifndef NDEBUG
    perror("Error setting socket option SO_BROADCAST");
#endif
    return 2;
  }
  iret = setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
  if (iret == -1) {
#ifndef NDEBUG
    perror("Error setting socket option IP_HDRINCL");
#endif
    return 3;
  }
  const struct sockaddr_in any = {.sin_family = AF_INET, .sin_port = 0, .sin_addr = {.s_addr = INADDR_ANY}};
  iret = bind(sock, (const struct sockaddr *)&any, sizeof(any));
  if (iret == -1) {
#ifndef NDEBUG
    perror("Error binding socket");
#endif
    return 4;
  }
  uint8_t buf[65536];
  uint8_t errs = 0;
  while (1) {
    ssize_t n = recv(sock, buf, sizeof(buf), 0);
    if (n == -1 && errno == EINTR) continue;
    if (n == -1) {
#ifndef NDEBUG
      perror("Error receiving datagram");
#endif
      if (++errs >= 10) {
#ifndef NDEBUG
        fprintf(stderr, "Too many consecutive errors\n");
#endif
        return 5;
      }
      continue;
    }
    errs = 0;
    if ((size_t)n > sizeof(buf)) {
#ifndef NDEBUG
      fprintf(stderr, "Overlong datagram of size %zd\n", n);
#endif
     continue;
    }
    if (n < 20) {
#ifndef NDEBUG
      fprintf(stderr, "Short IPv4 datagram of size %zd\n", n);
#endif
      continue;
    }
#ifndef NDEBUG
    if (buf[0] >> 4 != 4) {
      fprintf(stderr, "Not an IPv4 packet\n");
      continue;
    }
    if (buf[9] != IPPROTO_UDP) {
      fprintf(stderr, "Not a UDP packet\n");
      continue;
    }
    const uint16_t totlen = load16(&buf[2]);
    if (totlen != n) {
      fprintf(stderr, "Received %zd bytes but packet ip length field is %d bytes from " IPADDR "\n", n, totlen, IPBYTES(&buf[12]));
      continue;
    }
#endif
    const uint8_t ihl = buf[0] & 0xf;
#ifndef NDEBUG
    if (n < ihl * 4) {
      fprintf(stderr, "Header is %" PRIu8 " words but total length is only %zd bytes from " IPADDR "\n", ihl, n, IPBYTES(&buf[12]));
      continue;
    }
    const uint16_t cksum = checksum16(&buf[0], ihl*4);
    if (cksum != 0xffff) {
      fprintf(stderr, "Bad IPv4 checksum 0x%04" PRIx16 " from " IPADDR "\n", cksum, IPBYTES(&buf[12]));
      continue;
    }
#endif
    const uint32_t saddr = load32(&buf[12]);
    const uint32_t daddr = load32(&buf[16]);
    int db = 0, cnt = 0;
    for (const struct netw *netw = netws; netw->nn; ++netw) {
      if (netw->bc == daddr) {
        db = 1;
        if (saddr <= netw->nn || saddr >= netw->bc) {
#ifndef NDEBUG
          fprintf(stderr, "Ignoring directed broadcast to " IPADDR " from " IPADDR " outside corresponding network\n", IPBYTES(&buf[16]), IPBYTES(&buf[12]));
#endif
          cnt = 1;
        }
        break;
      }
    }
    if (cnt) continue;
    if (!db) {
#ifndef NDEBUG
      fprintf(stderr, "Not a directed broadcast; to " IPADDR "\n", IPBYTES(&buf[16]));
#endif
      continue;
    }
    const uint8_t *const udp = &buf[ihl * 4];
    const size_t udp_sz = n - ihl * 4;
    if (udp_sz < 8) {
#ifndef NDEBUG
      fprintf(stderr, "Short UDP datagram of size %zu from " IPADDR "\n", udp_sz, IPBYTES(&buf[12]));
#endif
      continue;
    }
#ifndef NDEBUG
    printf("Received %zd bytes from " IPADDR ":%d to " IPADDR ":%d\n", n, IPBYTES(&buf[12]), load16(&udp[0]), IPBYTES(&buf[16]), load16(&udp[2]));
#endif
    uint32_t paddr = daddr;
    for (const struct netw *netw = netws; netw->nn; ++netw) {
      if (netw->bc == daddr) {
        continue;
      }
      uint32_t cksum = (uint16_t)~load16(&buf[10]);
      cksum += (~paddr >> 16) + (~paddr & 0xffff);
      cksum += (netw->bc >> 16) + (netw->bc & 0xffff);
      while (cksum > 0xffff) {
        cksum = (uint16_t)(cksum) + (uint16_t)(cksum >> 16);
      }
      cksum = ~cksum;
      store16(&buf[10], cksum);
      store32(&buf[16], netw->bc);
      paddr = netw->bc;
#ifndef NDEBUG
      cksum = checksum16(&buf[0], ihl*4);
      if (cksum != 0xffff) {
        fprintf(stderr, "Bad recomputed IPv4 checksum 0x%04" PRIx32 " from " IPADDR "\n", cksum, IPBYTES(&buf[12]));
        store16(&buf[10], 0);
        cksum = checksum16(&buf[0], ihl*4);
        fprintf(stderr, "    checksum should maybe be 0x%04" PRIx32 " from " IPADDR "\n", cksum, IPBYTES(&buf[12]));
        continue;
      }
#endif
      const struct sockaddr_in da = {.sin_family = AF_INET, .sin_port = load16(&udp[2]), .sin_addr = {.s_addr = netw->bc}};
      while (1) {
        const ssize_t txn = sendto(sock, buf, n, 0, (const struct sockaddr *)&da, sizeof(da));
        if (txn == -1 && errno == EINTR) continue;
        if (txn == -1) {
#ifndef NDEBUG
          perror("Error sending datagram");
#endif
          break;
        }
#ifndef NDEBUG
        if (txn < n) {
          fprintf(stderr, "Short write %zd < %zd to " IPADDR ":%d\n", txn, n, IPBYTES(&buf[16]), load16(&udp[2]));
        }
        printf("    Sent %zd bytes from " IPADDR ":%d to " IPADDR ":%d\n", txn, IPBYTES(&buf[12]), load16(&udp[0]), IPBYTES(&buf[16]), load16(&udp[2]));
#endif
        break;
      }
    }
  }
  return EXIT_SUCCESS;
}

