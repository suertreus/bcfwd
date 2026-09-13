// bcfwd forwards directed UDP broadcast packets to all other attached networks,
// changing the destination address to the corresponding directed broadcast
// address.  Requires `CAP_NET_RAW` to open a raw UDP socket.

#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <inplace_vector>
#include <limits>
#include <string_view>
#include <utility>

#ifndef NDEBUG
#include <absl/base/internal/strerror.h>
#include <absl/strings/str_format.h>

#include <cstdio>
#include <span>
#endif

namespace {

#ifdef NDEBUG
template <typename T>
class span {
 public:
  explicit constexpr span(T* const ptr, const size_t len)
      : ptr_(ptr), len_(len) {}
  template <size_t N>
  explicit constexpr span(std::array<T, N>& arr)
      : span(arr.data(), arr.size()) {}
  constexpr span<T> subspan(
      const size_t start,
      const size_t len = std::numeric_limits<size_t>::max()) const {
    return span(ptr_ + start,
                len == std::numeric_limits<size_t>::max() ? len_ - start : len);
  }
  [[nodiscard]] constexpr T* data() const noexcept { return ptr_; }
  [[nodiscard]] constexpr size_t size() const noexcept { return len_; }
  [[nodiscard]] constexpr T& operator[](const size_t i) const noexcept {
    return ptr_[i];
  }
  operator span<const T>() const { return span<const T>(ptr_, len_); }

 private:
  T* ptr_;
  size_t len_;
};
#else
template <typename T>
using span = std::span<T>;
#endif

uint16_t load16(const span<const std::byte> b) {
  const uint16_t hi = std::to_integer<uint16_t>(b[0]) << 8u;
  const uint16_t lo = std::to_integer<uint16_t>(b[1]) << 0u;
  return hi | lo;
}
void store16(const span<std::byte> b, const uint16_t val) {
  b[0] = std::byte(val >> 8u);
  b[1] = std::byte(val);
}

void debug_perror(std::string_view msg) {
#ifdef NDEBUG
  (void)msg;
#else
  (void)absl::FPrintF(stderr, "%s: %s\n", msg,
                      absl::base_internal::StrError(errno));
#endif
}
#ifdef NDEBUG
template <typename... Args>
void debug_printf(const Args&...) {}
#else
template <typename... Args>
void debug_printf(const absl::FormatSpec<Args...>& format,
                  const Args&... args) {
  (void)absl::FPrintF(stdout, format, args...);
  (void)fputc('\n', stdout);
}
#endif
#ifdef NDEBUG
template <typename... Args>
void debug_errorf(const Args&...) {}
#else
template <typename... Args>
void debug_errorf(const absl::FormatSpec<Args...>& format,
                  const Args&... args) {
  (void)absl::FPrintF(stderr, format, args...);
  (void)fputc('\n', stderr);
}
#endif

class IPAddr {
 public:
  explicit constexpr IPAddr(const uint32_t val) : addr_(val) {}
  explicit constexpr IPAddr(const struct in_addr& a)
      : IPAddr(ntohl(a.s_addr)) {}
  explicit constexpr IPAddr(const span<const std::byte> b)
      : addr_{std::to_integer<uint32_t>(b[0]) << 24u |
              std::to_integer<uint32_t>(b[1]) << 16u |
              std::to_integer<uint32_t>(b[2]) << 8u |
              std::to_integer<uint32_t>(b[3]) << 0u} {}
  bool operator==(const IPAddr that) const { return this->addr_ == that.addr_; }
  auto operator<=>(const IPAddr that) const {
    return this->addr_ <=> that.addr_;
  }

  [[nodiscard]] constexpr IPAddr net(unsigned int prefix) const {
    return IPAddr(addr_ >> (32u - prefix) << (32u - prefix));
  }
  [[nodiscard]] constexpr IPAddr bc(unsigned int prefix) const {
    return IPAddr(addr_ | 0xffffffffu >> prefix);
  }
  [[nodiscard]] constexpr uint32_t as_uint32() const { return addr_; }

 private:
  uint32_t addr_;

#ifndef NDEBUG
  template <typename Sink>
  friend void AbslStringify(Sink& sink, const IPAddr ip) {
    (void)absl::Format(&sink, "%d.%d.%d.%d", ip.addr_ >> 24u & 0xffu,
                       ip.addr_ >> 16u & 0xffu, ip.addr_ >> 8u & 0xffu,
                       ip.addr_ >> 0u & 0xffu);
  }
#endif
};

class Net {
 public:
  constexpr Net(IPAddr addr, unsigned int prefix)
      : net_(addr.net(prefix)), bc_(addr.bc(prefix)) {}
  [[nodiscard]] constexpr IPAddr net() const { return net_; }
  [[nodiscard]] constexpr IPAddr bc() const { return bc_; }

 private:
  IPAddr net_, bc_;
};
std::inplace_vector<Net, 64> nets;

int load_local_nets() {
  const int sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  if (sock == -1) {
    debug_perror("Error opening rtnetlink socket");
    return 1;
  }
  const struct sockaddr_nl addr = {
      .nl_family = AF_NETLINK, .nl_pad = {}, .nl_pid = {}, .nl_groups = {}};
  struct sockaddr gen_addr;
  static_assert(sizeof(gen_addr) >= sizeof(addr));
  memcpy(&gen_addr, &addr, sizeof(addr));
  if (const int ret = bind(sock, &gen_addr, sizeof(addr)); ret == -1) {
    debug_perror("Error binding rtnetlink socket");
    return 2;
  }
  struct {
    struct nlmsghdr n;
    struct ifaddrmsg r;
  } req = {.n =
               {
                   .nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg)),
                   .nlmsg_type = RTM_GETADDR,
                   .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
                   .nlmsg_seq = 1,
                   .nlmsg_pid = {},
               },
           .r = {
               .ifa_family = AF_INET,
               .ifa_prefixlen = {},
               .ifa_flags = {},
               .ifa_scope = {},
               .ifa_index = {},
           }};
  while (true) {
    const ssize_t n = send(sock, &req, req.n.nlmsg_len, 0);
    if (n == -1 && errno == EINTR) {
      continue;
    }
    if (n == -1) {
      debug_perror("Error sending rtnetlink datagram");
      return 3;
    }
    if (std::cmp_less(n, req.n.nlmsg_len)) {
      debug_errorf("Short rtnetlink write %d < %u", n, req.n.nlmsg_len);
      return 4;
    }
    break;
  }
  while (true) {
    alignas(struct nlmsghdr) std::array<std::byte, 65536> buf;
    size_t rx_bytes;
    bool done = false;
    while (true) {
      const ssize_t n = recv(sock, buf.data(), buf.size(), MSG_TRUNC);
      if (n == -1 && errno == EINTR) {
        continue;
      }
      if (n == -1) {
        debug_perror("Error reading rtnetlink datagram");
        return 5;
      }
      if (std::cmp_greater(n, buf.size())) {
        debug_errorf("Received truncated rtnetlink datagram %d > %u", n,
                     buf.size());
        return 6;
      }
      rx_bytes = n;
      break;
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    for (const auto* msg = reinterpret_cast<const struct nlmsghdr*>(buf.data());
         NLMSG_OK(msg, rx_bytes); msg = NLMSG_NEXT(msg, rx_bytes)) {
      switch (msg->nlmsg_type) {
        case NLMSG_ERROR:
          debug_errorf("NLMSG_ERROR");
          return 7;
        case NLMSG_DONE:
          done = true;
          msg = NLMSG_NEXT(msg, rx_bytes);
        case RTM_NEWADDR:
          break;
        default:
          debug_errorf("Unexpected nlmsg_type %u", msg->nlmsg_type);
          if ((msg->nlmsg_flags & NLM_F_MULTI) == 0u) {
            debug_errorf("!NLM_F_MULTI");
            break;
          }
          continue;
      }
      if (done) {
        break;
      }
      const auto* const
          addrmsg =  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
          reinterpret_cast<struct ifaddrmsg*>(NLMSG_DATA(msg));
      if (addrmsg->ifa_family != AF_INET) {
        debug_errorf("Unexpected ifa_family %u", addrmsg->ifa_family);
        if ((msg->nlmsg_flags & NLM_F_MULTI) == 0u) {
          debug_errorf("!NLM_F_MULTI");
          break;
        }
        continue;
      }
      if (addrmsg->ifa_scope == RT_SCOPE_HOST) {
        // Disregard loopback address
        if ((msg->nlmsg_flags & NLM_F_MULTI) == 0u) {
          debug_errorf("!NLM_F_MULTI");
          break;
        }
        continue;
      }
      size_t payload_bytes = IFA_PAYLOAD(msg);
      for (
          const auto*
              attr =  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
          reinterpret_cast<const struct rtattr*>(IFA_RTA(addrmsg));
          RTA_OK(attr, payload_bytes); attr = RTA_NEXT(attr, payload_bytes)) {
        switch (attr->rta_type) {
          case IFA_BROADCAST: {
            struct in_addr addr;
            memcpy(&addr, RTA_DATA(attr), sizeof(addr));
            if (addrmsg->ifa_prefixlen == 0u) {
              debug_errorf("Broadcast address %v with prefix len of 0... wtf?",
                           IPAddr(addr.s_addr));
              continue;
            }
            if (!nets.try_emplace_back(IPAddr(addr), addrmsg->ifa_prefixlen)
                     .has_value()) {
              debug_errorf("Too many local interfaces; limit is %d",
                           nets.size());
              return 8;
            }
            break;
          }
          default:
            break;
        }
      }
      if (payload_bytes != 0u) {
        debug_errorf("%u trailing payload bytes after !RTA_OK", payload_bytes);
        return 9;
      }
      if ((msg->nlmsg_flags & NLM_F_MULTI) == 0) {
        debug_errorf("!NLM_F_MULTI");
        break;
      }
    }
    if (rx_bytes != 0u) {
      debug_errorf("%u trailing bytes after !NLMSG_OK", rx_bytes);
      return 10;
    }
    if (done) {
      break;
    }
  }
  if (const int ret = close(sock); ret == -1) {
    debug_perror("Error closing rtnetlink socket");
    return 11;
  }
  return 0;
}

#ifndef NDEBUG
uint16_t checksum16(const span<const std::byte> buf) {
  uint32_t sum = 0;
  for (size_t i = 0; i + 1 < buf.size(); i += 2) {
    sum += load16(buf.subspan(i, 2));
  }
  while (sum > 0xffffu) {
    sum = (sum & 0xffffu) + (sum >> 16u);
  }
  return sum;
}
#endif

bool checksum16_swap32(const span<std::byte> hdr, const size_t offset,
                       const uint32_t new_val) {
  const uint16_t prev_hi = load16(hdr.subspan(offset, 2));
  const uint16_t prev_lo = load16(hdr.subspan(offset + 2, 2));
  const uint16_t new_hi = new_val >> 16u;
  const uint16_t new_lo = new_val;
  uint32_t cksum = ~load16(hdr.subspan(10, 2));
  cksum &= 0xffffu;
  cksum += ~prev_lo + ~prev_hi + new_lo + new_hi;
  while (cksum > 0xffffu) {
    cksum = (cksum & 0xffffu) + (cksum >> 16u);
  }
  cksum = ~cksum;
  store16(hdr.subspan(10, 2), cksum);
  store16(hdr.subspan(offset, 2), new_hi);
  store16(hdr.subspan(offset + 2, 2), new_lo);
#ifndef NDEBUG
  cksum = checksum16(hdr);
  if (cksum != 0xffffu) {
    const IPAddr saddr(hdr.subspan(12, 4));
    debug_errorf("Bad recomputed IPv4 checksum 0x%04x from %v", cksum, saddr);
    store16(hdr.subspan(10, 2), 0);
    cksum = checksum16(hdr);
    debug_errorf("    checksum should maybe be 0x%04x from %v", cksum, saddr);
    return false;
  }
#endif
  return true;
}

}  // namespace

int main() {
  if (const int err = load_local_nets(); err) {
    debug_errorf("Error getting local addresses");
    return 0x10 + err;
  }
  for (const Net& net : nets) {
    debug_printf("Local network %v, broadcast %v", net.net(), net.bc());
  }
  const int sock = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
  if (sock == -1) {
    debug_perror("Error opening socket");
    return 1;
  }
  const int one = 1;
  if (const int ret =
          setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
      ret == -1) {
    debug_perror("Error setting socket option SO_BROADCAST");
    return 2;
  }
  if (const int ret =
          setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
      ret == -1) {
    debug_perror("Error setting socket option IP_HDRINCL");
    return 3;
  }
  const struct sockaddr_in any = {.sin_family = AF_INET,
                                  .sin_port = 0,
                                  .sin_addr = {.s_addr = INADDR_ANY},
                                  .sin_zero = {}};
  struct sockaddr gen_addr;
  static_assert(sizeof(gen_addr) >= sizeof(any));
  memcpy(&gen_addr, &any, sizeof(any));
  if (const int ret = bind(sock, &gen_addr, sizeof(any)); ret == -1) {
    debug_perror("Error binding socket");
    return 4;
  }
  std::array<std::byte, 65535> buf;
  int errs = 0;
  while (true) {
    const ssize_t n = recv(sock, buf.data(), buf.size(), MSG_TRUNC);
    if (n == -1 && errno == EINTR) {
      continue;
    }
    if (n == -1) {
      debug_perror("Error receiving datagram");
      if (++errs >= 10) {
        debug_errorf("Too many consecutive errors");
        return 5;
      }
      continue;
    }
    errs = 0;
    if (std::cmp_greater(n, buf.size())) {
      debug_errorf("Overlong datagram of size %d", n);
      continue;
    }
    const auto pkt = span(buf).subspan(0, n);
    if (pkt.size() < 20) {
      debug_errorf("Short IPv4 datagram of size %d", pkt.size());
      continue;
    }
#ifndef NDEBUG
    if ((pkt[0] >> 4u) != std::byte{4}) {
      debug_errorf("Not an IPv4 packet");
      continue;
    }
    if (pkt[9] != std::byte{IPPROTO_UDP}) {
      debug_errorf("Not a UDP packet");
      continue;
    }
#endif
    const IPAddr saddr(pkt.subspan(12, 4));
    const IPAddr daddr(pkt.subspan(16, 4));
#ifndef NDEBUG
    if (const uint16_t totlen = load16(pkt.subspan(2, 2));
        totlen != pkt.size()) {
      debug_errorf(
          "Received %u bytes but packet ip length field is %d bytes from %v",
          pkt.size(), totlen, saddr);
      continue;
    }
#endif
    const size_t ihl = std::to_integer<size_t>(pkt[0]) & 0xfu;
#ifndef NDEBUG
    if (pkt.size() < ihl * 4) {
      debug_errorf(
          "Header is %u words but total length is only %u bytes from %v", ihl,
          pkt.size(), saddr);
      continue;
    }
#endif
    const span<std::byte> hdr = pkt.subspan(0, ihl * 4);
#ifndef NDEBUG
    if (const uint16_t cksum = checksum16(hdr); cksum != 0xffffu) {
      debug_errorf("Bad IPv4 checksum 0x%04x from %v", cksum, saddr);
      continue;
    }
#endif
    bool db = false;
    bool cnt = false;
    for (const Net& net : nets) {
      if (net.bc() == daddr) {
        db = true;
        if (saddr <= net.net() || saddr >= net.bc()) {
          debug_errorf(
              "Ignoring directed broadcast to %v from %v outside corresponding "
              "network",
              daddr, saddr);
          cnt = true;
        }
        break;
      }
    }
    if (cnt) {
      continue;
    }
    if (!db) {
      debug_errorf("Not a directed broadcast; to %v", daddr);
      continue;
    }
    const span<const std::byte> udp = pkt.subspan(ihl * 4);
    if (udp.size() < 8) {
      debug_errorf("Short UDP datagram of size %u from %v", udp.size(), saddr);
      continue;
    }
    const uint16_t sport = load16(udp.subspan(0, 2));
    const uint16_t dport = load16(udp.subspan(2, 2));
    debug_printf("Received %u bytes from %v:%d to %v:%d", pkt.size(), saddr,
                 sport, daddr, dport);
    for (const Net& net : nets) {
      if (net.bc() == daddr) {
        continue;
      }
      if (!checksum16_swap32(hdr, 16u, net.bc().as_uint32())) {
        continue;
      }
      const struct sockaddr_in da = {
          .sin_family = AF_INET,
          .sin_port = dport,
          .sin_addr = {.s_addr = net.bc().as_uint32()},
          .sin_zero = {}};
      struct sockaddr gen_addr;
      static_assert(sizeof(gen_addr) >= sizeof(da));
      memcpy(&gen_addr, &da, sizeof(da));
      while (true) {
        const ssize_t txn =
            sendto(sock, pkt.data(), pkt.size(), 0, &gen_addr, sizeof(da));
        if (txn == -1 && errno == EINTR) {
          continue;
        }
        if (txn == -1) {
          debug_perror("Error sending datagram");
          break;
        }
        if (std::cmp_less(txn, pkt.size())) {
          debug_errorf("Short write %d < %u to %v:%d", txn, pkt.size(),
                       net.bc(), dport);
        }
        debug_printf("    Sent %d bytes from %v:%d to %v:%d", txn, saddr, sport,
                     net.bc(), dport);
        break;
      }
    }
  }
  return EXIT_SUCCESS;
}
