// bcfwd forwards directed UDP broadcast packets to all other attached networks,
// changing the destination address to the corresponding directed broadcast
// address.  Requires `CAP_NET_RAW` to open a raw UDP socket.

#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef NDEBUG
#include <inttypes.h>
#include <stdio.h>
#endif

#define IPADDR "%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8
#define IPWORD(addr) (uint8_t)((addr) >> 24), (uint8_t)((addr) >> 16), (uint8_t)((addr) >> 8), (uint8_t)((addr) >> 0)
#define IPBYTES(addr) (addr)[0], (addr)[1], (addr)[2], (addr)[3]

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

struct net {
  uint32_t nn, bc;
} nets[64];
size_t num_nets;
int local_nets_err;

static const struct net *local_nets(void) {
  const int sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  if (sock == -1) {
#ifndef NDEBUG
    perror("Error opening rtnetlink socket");
#endif
    local_nets_err = 1;
    return NULL;
  }
  const struct sockaddr_nl addr = {.nl_family = AF_NETLINK};
  int ret = bind(sock, (const struct sockaddr *)&addr, sizeof(addr));
  if (ret == -1) {
#ifndef NDEBUG
    perror("Error binding rtnetlink socket");
#endif
    local_nets_err = 2;
    return NULL;
  }
  struct {
    struct nlmsghdr n;
    struct ifaddrmsg r;
  } req = {.n = {
             .nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg)),
             .nlmsg_type = RTM_GETADDR,
             .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
             .nlmsg_seq = 1,
           },
           .r = {
             .ifa_family = AF_INET,
           }};
  while (1) {
    const ssize_t n = send(sock, &req, req.n.nlmsg_len, 0);
    if (n == -1 && errno == EINTR) continue;
    if (n == -1) {
#ifndef NDEBUG
      perror("Error sending rtnetlink datagram");
#endif
      local_nets_err = 3;
      return NULL;
    }
    if (n < req.n.nlmsg_len) {
#ifndef NDEBUG
      fprintf(stderr, "Short rtnetlink write %zd < %zu", n, (size_t)req.n.nlmsg_len);
#endif
      local_nets_err = 4;
      return NULL;
    }
    break;
  }
  while (1) {
    uint8_t buf[4096];
    size_t rx_bytes;
    int done = 0;
    while (1) {
      const ssize_t n = recv(sock, buf, sizeof(buf), MSG_TRUNC);
      if (n == -1 && errno == EINTR) continue;
      if (n == -1) {
#ifndef NDEBUG
        perror("Error reading rtnetlink datagram");
#endif
        local_nets_err = 5;
        return NULL;
      }
      if ((size_t)n > sizeof(buf)) {
#ifndef NDEBUG
        fprintf(stderr, "Received truncated rtnetlink datagram %zd > %zu\n", n, sizeof(buf));
#endif
        local_nets_err = 6;
        return NULL;
      }
      rx_bytes = n;
      break;
    }
    for (const struct nlmsghdr *msg = (const struct nlmsghdr *)buf; NLMSG_OK(msg, rx_bytes); msg = NLMSG_NEXT(msg, rx_bytes)) {
      switch (msg->nlmsg_type) {
        case NLMSG_ERROR:
#ifndef NDEBUG
          fprintf(stderr, "NLMSG_ERROR\n");
#endif
          local_nets_err = 7;
          return NULL;
        case NLMSG_DONE:
          done = 1;
          msg = NLMSG_NEXT(msg, rx_bytes);
        case RTM_NEWADDR: break;
        default:
#ifndef NDEBUG
          fprintf(stderr, "Unexpected nlmsg_type %" PRIu16 "\n", (uint16_t)msg->nlmsg_type);
#endif
          if (!(msg->nlmsg_flags & NLM_F_MULTI)) {
#ifndef NDEBUG
            fprintf(stderr, "!NLM_F_MULTI\n");
#endif
            break;
          }
          continue;
      }
      if (done) break;
      const struct ifaddrmsg *addrmsg = (struct ifaddrmsg *)NLMSG_DATA(msg);
      if (addrmsg->ifa_family != AF_INET) {
#ifndef NDEBUG
        fprintf(stderr, "Unexpected ifa_family %u\n", (unsigned int)addrmsg->ifa_family);
#endif
        if (!(msg->nlmsg_flags & NLM_F_MULTI)) {
#ifndef NDEBUG
          fprintf(stderr, "!NLM_F_MULTI\n");
#endif
          break;
        }
        continue;
      }
      if (addrmsg->ifa_scope == RT_SCOPE_HOST) {
        // Disregard loopback address
        if (!(msg->nlmsg_flags & NLM_F_MULTI)) {
#ifndef NDEBUG
          fprintf(stderr, "!NLM_F_MULTI\n");
#endif
          break;
        }
        continue;
      }
      size_t payload_bytes = IFA_PAYLOAD(msg);
      for (const struct rtattr *attr = (const struct rtattr *)IFA_RTA(addrmsg); RTA_OK(attr, payload_bytes); attr = RTA_NEXT(attr, payload_bytes)) {
        switch (attr->rta_type) {
          case IFA_BROADCAST: {
            const struct in_addr *addr = (const struct in_addr *)RTA_DATA(attr);
            nets[num_nets].nn = load32((const uint8_t *)&addr->s_addr) & 0xffffffff00000000 >> addrmsg->ifa_prefixlen;
            nets[num_nets++].bc = load32((const uint8_t *)&addr->s_addr);
            break;
          }
        }
      }
      if (payload_bytes) {
#ifndef NDEBUG
        fprintf(stderr, "%zu trailing payload bytes after !RTA_OK\n", payload_bytes);
#endif
        local_nets_err = 8;
        return NULL;
      }
      if (!(msg->nlmsg_flags & NLM_F_MULTI)) {
#ifndef NDEBUG
        fprintf(stderr, "!NLM_F_MULTI\n");
#endif
        break;
      }
    }
    if (rx_bytes) {
#ifndef NDEBUG
      fprintf(stderr, "%zu trailing bytes after !NLMSG_OK\n", rx_bytes);
#endif
      local_nets_err = 9;
      return NULL;
    }
    if (done) break;
  }
  ret = close(sock);
  if (ret == -1) {
#ifndef NDEBUG
    perror("Error closing rtnetlink socket");
#endif
    local_nets_err = 10;
    return NULL;
  }
  return nets;
}

#ifndef NDEBUG
static uint16_t checksum16(const uint8_t *const buf, const size_t sz) {
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
  const struct net *nets = local_nets();
  if (!nets) {
#ifndef NDEBUG
    fprintf(stderr, "Error getting local addresses\n");
#endif
    return 0x10 + local_nets_err;
  }
#ifndef NDEBUG
  for (const struct net *net = nets; net->nn; ++net) {
    printf("Local network " IPADDR ", broadcast " IPADDR "\n", IPWORD(net->nn), IPWORD(net->bc));
  }
#endif
  const int sock = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
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
    for (const struct net *net = nets; net->nn; ++net) {
      if (net->bc == daddr) {
        db = 1;
        if (saddr <= net->nn || saddr >= net->bc) {
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
    for (const struct net *net = nets; net->nn; ++net) {
      if (net->bc == daddr) {
        continue;
      }
      uint32_t cksum = (uint16_t)~load16(&buf[10]);
      cksum += (~paddr >> 16) + (~paddr & 0xffff);
      cksum += (net->bc >> 16) + (net->bc & 0xffff);
      while (cksum > 0xffff) {
        cksum = (uint16_t)(cksum) + (uint16_t)(cksum >> 16);
      }
      cksum = ~cksum;
      store16(&buf[10], cksum);
      store32(&buf[16], net->bc);
      paddr = net->bc;
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
      const struct sockaddr_in da = {.sin_family = AF_INET, .sin_port = load16(&udp[2]), .sin_addr = {.s_addr = net->bc}};
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

