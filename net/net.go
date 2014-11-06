// package sanet provides conversions between net.Addr and syscall.Sockaddr
package sanet

import (
	"net"
	"syscall"
)

// NetAddrToSockaddr converts a net.Addr to a syscall.Sockaddr.
// Returns nil if the input is invalid or conversion is not possible.
func NetAddrToSockaddr(addr net.Addr) syscall.Sockaddr {
	switch addr := addr.(type) {
	default:
		return nil
	case *net.IPAddr:
		return IPAddrToSockaddr(addr)
	case *net.TCPAddr:
		return TCPAddrToSockaddr(addr)
	case *net.UDPAddr:
		return UDPAddrToSockaddr(addr)
	case *net.UnixAddr:
		sa, _ := UnixAddrToSockaddr(addr)
		return sa
	}
}

// IPAndZoneToSockaddr converts a net.IP (with optional IPv6 Zone) to a syscall.Sockaddr
// Returns nil if conversion fails.
func IPAndZoneToSockaddr(ip net.IP, zone string) syscall.Sockaddr {
	switch {
	default:
		return nil

	case ip.To4() != nil:
		var buf [4]byte
		copy(buf[:], ip[12:16]) // last 4 bytes
		return &syscall.SockaddrInet4{Addr: buf}

	case ip.To16() != nil:
		var buf [16]byte
		copy(buf[:], ip)
		return &syscall.SockaddrInet6{Addr: buf, ZoneId: uint32(IP6ZoneToInt(zone))}
	}
}

// IPAddrToSockaddr converts a net.IPAddr to a syscall.Sockaddr.
// Returns nil if conversion fails.
func IPAddrToSockaddr(addr *net.IPAddr) syscall.Sockaddr {
	return IPAndZoneToSockaddr(addr.IP, addr.Zone)
}

// TCPAddrToSockaddr converts a net.TCPAddr to a syscall.Sockaddr.
// Returns nil if conversion fails.
func TCPAddrToSockaddr(addr *net.TCPAddr) syscall.Sockaddr {
	sa := IPAndZoneToSockaddr(addr.IP, addr.Zone)
	if sa == nil {
		return sa
	}

	switch sa := sa.(type) {
	default:
		return nil
	case *syscall.SockaddrInet4:
		sa.Port = addr.Port
		return sa
	case *syscall.SockaddrInet6:
		sa.Port = addr.Port
		return sa
	}
}

// UDPAddrToSockaddr converts a net.UDPAddr to a syscall.Sockaddr.
// Returns nil if conversion fails.
func UDPAddrToSockaddr(addr *net.UDPAddr) syscall.Sockaddr {
	sa := IPAndZoneToSockaddr(addr.IP, addr.Zone)
	if sa == nil {
		return sa
	}

	switch sa := sa.(type) {
	default:
		return nil
	case *syscall.SockaddrInet4:
		sa.Port = addr.Port
		return sa
	case *syscall.SockaddrInet6:
		sa.Port = addr.Port
		return sa
	}
}

// UnixAddrToSockaddr converts a net.UnixAddr to a syscall.Sockaddr, and returns
// the type (syscall.SOCK_STREAM, syscall.SOCK_DGRAM, syscall.SOCK_SEQPACKET)
// Returns (nil, 0) if conversion fails.
func UnixAddrToSockaddr(addr *net.UnixAddr) (syscall.Sockaddr, int) {
	t := 0
	switch addr.Net {
	default:
		return nil, 0
	case "unix":
		t = syscall.SOCK_STREAM
	case "unixgram":
		t = syscall.SOCK_DGRAM
	case "unixpacket":
		t = syscall.SOCK_SEQPACKET
	}
	return &syscall.SockaddrUnix{Name: addr.Name}, t
}

// from: go/src/pkg/net/unixsock_posix.go

// SockaddrToUnixAddr converts a syscall.Sockaddr to a net.UnixAddr
// Returns nil if conversion fails.
func SockaddrToUnixAddr(sa syscall.Sockaddr) *net.UnixAddr {
	if s, ok := sa.(*syscall.SockaddrUnix); ok {
		return &net.UnixAddr{Name: s.Name, Net: "unix"}
	}
	return nil
}

// SockaddrToUnixgramAddr converts a syscall.Sockaddr to a net.UnixAddr
// Returns nil if conversion fails.
func SockaddrToUnixgramAddr(sa syscall.Sockaddr) *net.UnixAddr {
	if s, ok := sa.(*syscall.SockaddrUnix); ok {
		return &net.UnixAddr{Name: s.Name, Net: "unixgram"}
	}
	return nil
}

// SockaddrToUnixpacketAddr converts a syscall.Sockaddr to a net.UnixAddr
// Returns nil if conversion fails.
func SockaddrToUnixpacketAddr(sa syscall.Sockaddr) *net.UnixAddr {
	if s, ok := sa.(*syscall.SockaddrUnix); ok {
		return &net.UnixAddr{Name: s.Name, Net: "unixpacket"}
	}
	return nil
}

// from: go/src/pkg/net/ipsock.go

// IP6ZoneToString converts an IP6 Zone syscall int to a net string
// returns "" if zone is 0
func IP6ZoneToString(zone int) string {
	if zone == 0 {
		return ""
	}
	if ifi, err := net.InterfaceByIndex(zone); err == nil {
		return ifi.Name
	}
	return itod(uint(zone))
}

// IP6ZoneToInt converts an IP6 Zone net string to a syscall int
// returns 0 if zone is ""
func IP6ZoneToInt(zone string) int {
	if zone == "" {
		return 0
	}
	if ifi, err := net.InterfaceByName(zone); err == nil {
		return ifi.Index
	}
	n, _, _ := dtoi(zone, 0)
	return n
}

// from: go/src/pkg/net/parse.go

// Convert i to decimal string.
func itod(i uint) string {
	if i == 0 {
		return "0"
	}

	// Assemble decimal in reverse order.
	var b [32]byte
	bp := len(b)
	for ; i > 0; i /= 10 {
		bp--
		b[bp] = byte(i%10) + '0'
	}

	return string(b[bp:])
}

// Bigger than we need, not too big to worry about overflow
const big = 0xFFFFFF

// Decimal to integer starting at &s[i0].
// Returns number, new offset, success.
func dtoi(s string, i0 int) (n int, i int, ok bool) {
	n = 0
	for i = i0; i < len(s) && '0' <= s[i] && s[i] <= '9'; i++ {
		n = n*10 + int(s[i]-'0')
		if n >= big {
			return 0, i, false
		}
	}
	if i == i0 {
		return 0, i, false
	}
	return n, i, true
}
