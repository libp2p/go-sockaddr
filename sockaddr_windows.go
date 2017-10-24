package sockaddr

import (
	"golang.org/x/sys/unix"
	"unsafe"
)

func sockaddrToAny(sa unix.Sockaddr) (*unix.RawSockaddrAny, Socklen, error) {
	if sa == nil {
		return nil, 0, unix.EINVAL
	}

	switch sa := sa.(type) {
	case *unix.SockaddrInet4:
		if sa.Port < 0 || sa.Port > 0xFFFF {
			return nil, 0, unix.EINVAL
		}
		var raw unix.RawSockaddrInet4
		raw.Family = unix.AF_INET
		p := (*[2]byte)(unsafe.Pointer(&raw.Port))
		p[0] = byte(sa.Port >> 8)
		p[1] = byte(sa.Port)
		for i := 0; i < len(sa.Addr); i++ {
			raw.Addr[i] = sa.Addr[i]
		}
		return (*unix.RawSockaddrAny)(unsafe.Pointer(&raw)), int32(unsafe.Sizeof(raw)), nil

	case *unix.SockaddrInet6:
		if sa.Port < 0 || sa.Port > 0xFFFF {
			return nil, 0, unix.EINVAL
		}
		var raw unix.RawSockaddrInet6
		raw.Family = unix.AF_INET6
		p := (*[2]byte)(unsafe.Pointer(&raw.Port))
		p[0] = byte(sa.Port >> 8)
		p[1] = byte(sa.Port)
		raw.Scope_id = sa.ZoneId
		for i := 0; i < len(sa.Addr); i++ {
			raw.Addr[i] = sa.Addr[i]
		}
		return (*unix.RawSockaddrAny)(unsafe.Pointer(&raw)), int32(unsafe.Sizeof(raw)), nil

	case *unix.SockaddrUnix:
		return nil, 0, unix.EWINDOWS
	}
	return nil, 0, unix.EAFNOSUPPORT
}

func anyToSockaddr(rsa *unix.RawSockaddrAny) (unix.Sockaddr, error) {
	if rsa == nil {
		return nil, 0, unix.EINVAL
	}

	switch rsa.Addr.Family {
	case unix.AF_UNIX:
		return nil, unix.EWINDOWS

	case unix.AF_INET:
		pp := (*unix.RawSockaddrInet4)(unsafe.Pointer(rsa))
		sa := new(unix.SockaddrInet4)
		p := (*[2]byte)(unsafe.Pointer(&pp.Port))
		sa.Port = int(p[0])<<8 + int(p[1])
		for i := 0; i < len(sa.Addr); i++ {
			sa.Addr[i] = pp.Addr[i]
		}
		return sa, nil

	case unix.AF_INET6:
		pp := (*unix.RawSockaddrInet6)(unsafe.Pointer(rsa))
		sa := new(unix.SockaddrInet6)
		p := (*[2]byte)(unsafe.Pointer(&pp.Port))
		sa.Port = int(p[0])<<8 + int(p[1])
		sa.ZoneId = pp.Scope_id
		for i := 0; i < len(sa.Addr); i++ {
			sa.Addr[i] = pp.Addr[i]
		}
		return sa, nil
	}
	return nil, unix.EAFNOSUPPORT
}
