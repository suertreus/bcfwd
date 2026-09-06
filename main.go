// bcfwd forwards directed UDP broadcast packets to all other attached networks,
// changing the destination address to the corresponding directed broadcast
// address.  Requires `CAP_NET_RAW` to open a raw UDP socket.

package main

import (
  "encoding/binary"
  "errors"
  "fmt"
  "golang.org/x/sys/unix"
  "log"
  "net"
  "os"
)

const debug = true

type netw struct {
  nn, bc uint32
}

func localNets() ([]netw, error) {
  strs, err := net.InterfaceAddrs()
  if err != nil {
    return nil, fmt.Errorf("failed to get interface addresses: %w", err)
  }
  netws := make([]netw, 0, len(strs))
  for _, str := range strs {
    ip, net, err := net.ParseCIDR(str.String())
    if err != nil {
      return nil, fmt.Errorf("failed to parse interface address %q: %w", str, err)
    }
    if ip.IsLoopback() {
      continue
    }
    if len(net.IP) != 4 || len(net.Mask) != 4 {
      continue
    }
    netws = append(netws, netw{nn: binary.BigEndian.Uint32(net.IP), bc: binary.BigEndian.Uint32(net.IP) | ^binary.BigEndian.Uint32(net.Mask)})
  }
  return netws, nil
}

func checksum16(buf []byte) uint16 {
  var sum uint32
  for i := 0; i + 1 < len(buf); i += 2 {
    sum += uint32(binary.BigEndian.Uint16(buf[i:i + 2]))
  }
  for sum > 0xffff {
    sum = uint32(uint16(sum) + uint16(sum >> 16));
  }
  return uint16(sum)
}

func main() {
  netws, err := localNets()
  if err != nil {
    if debug {
      log.Fatalf("Error getting local networks: %v", err)
    }
    os.Exit(1)
  }
  if debug {
    for _, netw := range netws {
      log.Printf("Local network %d.%d.%d.%d, broadcast %d.%d.%d.%d",
                 netw.nn >> 24 & 0xff, netw.nn >> 16 & 0xff, netw.nn >> 8 & 0xff, netw.nn >> 0 & 0xff,
                 netw.bc >> 24 & 0xff, netw.bc >> 16 & 0xff, netw.bc >> 8 & 0xff, netw.bc >> 0 & 0xff)
    }
  }
  sock, err := unix.Socket(unix.PF_INET, unix.SOCK_RAW, unix.IPPROTO_UDP)
  if err != nil {
    if debug {
      log.Fatalf("Error opening socket: %v", err)
    }
    os.Exit(2)
  }
  if err = unix.SetsockoptInt(sock, unix.SOL_SOCKET, unix.SO_BROADCAST, 1); err != nil {
    if debug {
      log.Fatalf("Error setting socket option SO_BROADCAST: %v", err)
    }
    os.Exit(3)
  }
  if err = unix.SetsockoptInt(sock, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
    if debug {
      log.Fatalf("Error setting socket option IP_HDRINCL: %v", err)
    }
    os.Exit(4)
  }
  if err := unix.Bind(sock, &unix.SockaddrInet4{}); err != nil {
    if debug {
      log.Fatalf("Error binding socket: %v", err)
    }
    os.Exit(5)
  }
  var buf [65536]byte
  var errs int
Recvmsg:
  for {
    n, _, rf, src, err := unix.Recvmsg(sock, buf[:], nil, 0)
    if err != nil {
      if errors.Is(err, unix.EINTR) {
        continue
      }
      if debug {
        log.Printf("Error receiving datagram: %v", err)
      }
      errs++
      if errs >= 10 {
        if debug {
          log.Fatal("Too many consecutive errors")
        }
        os.Exit(6)
      }
      continue
    }
    errs = 0
    var src4 *unix.SockaddrInet4
    if debug {
      var ok bool
      if src4, ok = src.(*unix.SockaddrInet4); !ok {
        log.Print("Source address is not a SockaddrInet4")
        continue
      }
    }
    if rf & unix.MSG_TRUNC != 0 {
      if debug {
        log.Printf("Truncated datagram of size %d from %d.%d.%d.%d", n, src4.Addr[0], src4.Addr[1], src4.Addr[2], src4.Addr[3])
      }
      continue
    }
    if n > len(buf) {
      if debug {
        log.Printf("Overlong datagram of size %d from %d.%d.%d.%d", n, src4.Addr[0], src4.Addr[1], src4.Addr[2], src4.Addr[3])
      }
     continue
    }
    buf := buf[:n]
    if len(buf) < 20 {
      if debug {
        log.Printf("Short IPv4 datagram of size %d from %d.%d.%d.%d", len(buf), src4.Addr[0], src4.Addr[1], src4.Addr[2], src4.Addr[3])
      }
      continue
    }
    if debug {
      if ver := buf[0] >> 4; ver != 4 {
        log.Print("Not an IPv4 packet")
        continue
      }
      if proto := buf[9]; proto != unix.IPPROTO_UDP {
        log.Print("Not a UDP packet")
        continue
      }
      if totlen := binary.BigEndian.Uint16(buf[2:4]); int(totlen) != len(buf) {
        log.Printf("Received %d bytes but packet ip length field is %d bytes from %d.%d.%d.%d", len(buf), totlen, src4.Addr[0], src4.Addr[1], src4.Addr[2], src4.Addr[3])
        continue
      } else if ihl := buf[0] & 0xf; n < int(ihl) * 4 {
        log.Printf("Header is %d words but total length is only %d bytes from %d.%d.%d.%d", ihl, n, src4.Addr[0], src4.Addr[1], src4.Addr[2], src4.Addr[3])
        continue
      } else if cksum := checksum16(buf[0:ihl*4]); cksum != 0xffff {
        log.Printf("Bad IPv4 checksum 0x%04x from %d.%d.%d.%d", cksum, src4.Addr[0], src4.Addr[1], src4.Addr[2], src4.Addr[3])
        continue
      }
    }
    saddr := binary.BigEndian.Uint32(buf[12:16])
    daddr := binary.BigEndian.Uint32(buf[16:20])
    var db bool
    for _, netw := range netws {
      if netw.bc == daddr {
        db = true
        if saddr <= netw.nn || saddr >= netw.bc {
          if debug {
            log.Printf("Ignoring directed broadcast to %d.%d.%d.%d from %d.%d.%d.%d outside corresponding network",
                       buf[16], buf[17], buf[18], buf[19],
                       buf[12], buf[13], buf[14], buf[15])
          }
          continue Recvmsg
        }
        break
      }
    }
    if !db {
      if debug {
        log.Printf("Not a directed broadcast; to %d.%d.%d.%d", buf[16], buf[17], buf[18], buf[19])
      }
      continue
    }
    ihl := buf[0] & 0xf
    udp := buf[ihl * 4:]
    if len(udp) < 8 {
      if debug {
        log.Printf("Short UDP datagram of size %d from %d.%d.%d.%d", len(udp), src4.Addr[0], src4.Addr[1], src4.Addr[2], src4.Addr[3])
      }
      continue
    }
    if debug {
      log.Printf("Received %d bytes from %d.%d.%d.%d:%d to %d.%d.%d.%d:%d", len(buf),
                 buf[12], buf[13], buf[14], buf[15], binary.BigEndian.Uint16(udp[0:2]),
                 buf[16], buf[17], buf[18], buf[19], binary.BigEndian.Uint16(udp[2:4]))
    }
    paddr := daddr
    for _, netw := range netws {
      if netw.bc == daddr {
        continue
      }
      cksum := uint32(^binary.BigEndian.Uint16(buf[10:12]))
      cksum += ^paddr >> 16 + ^paddr & 0xffff
      cksum += netw.bc >> 16 + netw.bc & 0xffff
      for cksum > 0xffff {
        cksum = uint32(uint16(cksum) + uint16(cksum >> 16));
      }
      cksum = ^cksum
      binary.BigEndian.PutUint16(buf[10:12], uint16(cksum))
      binary.BigEndian.PutUint32(buf[16:20], netw.bc)
      paddr = netw.bc
      if debug {
        if cksum := checksum16(buf[0:ihl*4]); cksum != 0xffff {
          log.Printf("Bad recomputed IPv4 checksum 0x%04x from %d.%d.%d.%d", cksum, src4.Addr[0], src4.Addr[1], src4.Addr[2], src4.Addr[3])
          continue
        }
      }
      da := unix.SockaddrInet4{
        Port: int(binary.BigEndian.Uint16(udp[2:4])),
        Addr: [4]byte{buf[16], buf[17], buf[18], buf[19]},
      }
      for {
        err := unix.Sendto(sock, buf, 0, &da)
        if err != nil {
          if errors.Is(err, unix.EINTR) {
            continue
          }
          if debug {
            log.Printf("Error sending datagram: %v", err)
          }
          break
        }
        if debug {
          log.Printf("    Sent %d bytes from %d.%d.%d.%d:%d to %d.%d.%d.%d:%d", len(buf),
                     buf[12], buf[13], buf[14], buf[15], binary.BigEndian.Uint16(udp[0:2]),
                     buf[16], buf[17], buf[18], buf[19], binary.BigEndian.Uint16(udp[2:4]))
        }
        break
      }
    }
  }
}

