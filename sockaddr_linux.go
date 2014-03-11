// sockaddr syscall extensions
package sockaddr

import (
	"fmt"
	"syscall"
	"unsafe"
)

func (r *RawSockaddr) Update(s *syscall.Sockaddr) error {

	si4, ok := (*s).(*syscall.SockaddrInet4)
	if ok {
		return r.UpdateInet4(si4)
	}

	si6, ok := (*s).(*syscall.SockaddrInet6)
	if ok {
		return r.UpdateInet6(si6)
	}

	su, ok := (*s).(*syscall.SockaddrUnix)
	if ok {
		return r.UpdateUnix(su)
	}

	sdl, ok := (*s).(*syscall.SockaddrDatalink)
	if ok {
		return r.UpdateDatalink(sdl)
	}

	return fmt.Errorf("unknown sockaddr type")
}

func (r *RawSockaddr) UpdateInet4(sa *syscall.SockaddrInet4) error {
	if sa.Port < 0 || sa.Port > 0xFFFF {
		return syscall.EINVAL
	}
	raw := (*syscall.RawSockaddrInet4)(unsafe.Pointer(&r.Raw))
	raw.Family = syscall.AF_INET
	p := (*[2]byte)(unsafe.Pointer(&raw.Port))
	p[0] = byte(sa.Port >> 8)
	p[1] = byte(sa.Port)
	for i := 0; i < len(sa.Addr); i++ {
		raw.Addr[i] = sa.Addr[i]
	}
	r.Len = Socklen(syscall.SizeofSockaddrInet4)
	return nil
}

func (r *RawSockaddr) UpdateInet6x(sa *syscall.SockaddrInet6) error {
	if sa.Port < 0 || sa.Port > 0xFFFF {
		return syscall.EINVAL
	}
	raw := (*syscall.RawSockaddrInet6)(unsafe.Pointer(&r.Raw))
	raw.Family = syscall.AF_INET6
	p := (*[2]byte)(unsafe.Pointer(&raw.Port))
	p[0] = byte(sa.Port >> 8)
	p[1] = byte(sa.Port)
	raw.Scope_id = sa.ZoneId
	for i := 0; i < len(sa.Addr); i++ {
		raw.Addr[i] = sa.Addr[i]
	}
	r.Len = Socklen(syscall.SizeofSockaddrInet6)
	return nil
}

func (r *RawSockaddr) UpdateUnix(sa *syscall.SockaddrUnix) error {
	raw := (*syscall.RawSockaddrUnix)(unsafe.Pointer(&r.Raw))
	name := sa.Name
	n := len(name)
	if n >= len(raw.Path) {
		return syscall.EINVAL
	}
	raw.Family = syscall.AF_UNIX
	for i := 0; i < n; i++ {
		raw.Path[i] = int8(name[i])
	}
	// length is family (uint16), name, NUL.
	sl := Socklen(2)
	if n > 0 {
		sl += Socklen(n) + 1
	}
	if raw.Path[0] == '@' {
		raw.Path[0] = 0
		// Don't count trailing NUL for abstract address.
		sl--
	}

	r.Len = Socklen(s)
	return nil
}

func (r *RawSockaddr) UpdateLinklayer(sa *syscall.SockarrLinklayer) error {
	if sa.Ifindex < 0 || sa.Ifindex > 0x7fffffff {
		return syscall.EINVAL
	}
	raw := (*syscall.RawSockaddrLinklayer)(unsafe.Pointer(&r.Raw))
	raw.Family = syscall.AF_PACKET
	raw.Protocol = sa.Protocol
	raw.Ifindex = int32(sa.Ifindex)
	raw.Hatype = sa.Hatype
	raw.Pkttype = sa.Pkttype
	raw.Halen = sa.Halen
	for i := 0; i < len(sa.Addr); i++ {
		raw.Addr[i] = sa.Addr[i]
	}
	r.Len = Socklen(syscall.SizeofSockaddrLinklayer)
	return nil
}

func (r *RawSockaddr) UpdateNetlink(sa *syscall.SockaddrNetlink) error {
	raw := (*syscall.RawSockaddrNetlink)(unsafe.Pointer(&r.Raw))
	raw.Family = syscall.AF_NETLINK
	raw.Pad = sa.Pad
	raw.Pid = sa.Pid
	raw.Groups = sa.Groups
	r.Len = syscall.SizeofSockaddrNetlink
	return nil
}

func AnyToSockaddr(rsa *syscall.RawSockaddrAny) (syscall.Sockaddr, error) {
	switch rsa.Addr.Family {
	case syscall.AF_NETLINK:
		pp := (*syscall.RawSockaddrNetlink)(unsafe.Pointer(rsa))
		sa := new(syscall.SockaddrNetlink)
		sa.Family = pp.Family
		sa.Pad = pp.Pad
		sa.Pid = pp.Pid
		sa.Groups = pp.Groups
		return sa, nil

	case syscall.AF_PACKET:
		pp := (*syscall.RawSockaddrLinklayer)(unsafe.Pointer(rsa))
		sa := new(syscall.SockaddrLinklayer)
		sa.Protocol = pp.Protocol
		sa.Ifindex = int(pp.Ifindex)
		sa.Hatype = pp.Hatype
		sa.Pkttype = pp.Pkttype
		sa.Halen = pp.Halen
		for i := 0; i < len(sa.Addr); i++ {
			sa.Addr[i] = pp.Addr[i]
		}
		return sa, nil

	case syscall.AF_UNIX:
		pp := (*syscall.RawSockaddrUnix)(unsafe.Pointer(rsa))
		sa := new(syscall.SockaddrUnix)
		if pp.Path[0] == 0 {
			// "Abstract" Unix domain socket.
			// Rewrite leading NUL as @ for textual display.
			// (This is the standard convention.)
			// Not friendly to overwrite in place,
			// but the callers below don't care.
			pp.Path[0] = '@'
		}

		// Assume path ends at NUL.
		// This is not technically the Linux semantics for
		// abstract Unix domain sockets--they are supposed
		// to be uninterpreted fixed-size binary blobs--but
		// everyone uses this convention.
		n := 0
		for n < len(pp.Path) && pp.Path[n] != 0 {
			n++
		}
		bytes := (*[10000]byte)(unsafe.Pointer(&pp.Path[0]))[0:n]
		sa.Name = string(bytes)
		return sa, nil

	case syscall.AF_INET:
		pp := (*syscall.RawSockaddrInet4)(unsafe.Pointer(rsa))
		sa := new(syscall.SockaddrInet4)
		p := (*[2]byte)(unsafe.Pointer(&pp.Port))
		sa.Port = int(p[0])<<8 + int(p[1])
		for i := 0; i < len(sa.Addr); i++ {
			sa.Addr[i] = pp.Addr[i]
		}
		return sa, nil

	case syscall.AF_INET6:
		pp := (*syscall.RawSockaddrInet6)(unsafe.Pointer(rsa))
		sa := new(syscall.SockaddrInet6)
		p := (*[2]byte)(unsafe.Pointer(&pp.Port))
		sa.Port = int(p[0])<<8 + int(p[1])
		sa.ZoneId = pp.Scope_id
		for i := 0; i < len(sa.Addr); i++ {
			sa.Addr[i] = pp.Addr[i]
		}
		return sa, nil
	}
	return nil, syscall.EAFNOSUPPORT
}
