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
	raw.Len = syscall.SizeofSockaddrInet4
	raw.Family = syscall.AF_INET
	p := (*[2]byte)(unsafe.Pointer(&raw.Port))
	p[0] = byte(sa.Port >> 8)
	p[1] = byte(sa.Port)
	for i := 0; i < len(sa.Addr); i++ {
		raw.Addr[i] = sa.Addr[i]
	}
	r.Len = Socklen(raw.Len)
	return nil
}

func (r *RawSockaddr) UpdateInet6(sa *syscall.SockaddrInet6) error {
	if sa.Port < 0 || sa.Port > 0xFFFF {
		return syscall.EINVAL
	}
	raw := (*syscall.RawSockaddrInet6)(unsafe.Pointer(&r.Raw))
	raw.Len = syscall.SizeofSockaddrInet6
	raw.Family = syscall.AF_INET6
	p := (*[2]byte)(unsafe.Pointer(&raw.Port))
	p[0] = byte(sa.Port >> 8)
	p[1] = byte(sa.Port)
	raw.Scope_id = sa.ZoneId
	for i := 0; i < len(sa.Addr); i++ {
		raw.Addr[i] = sa.Addr[i]
	}
	r.Len = Socklen(raw.Len)
	return nil
}

func (r *RawSockaddr) UpdateUnix(sa *syscall.SockaddrUnix) error {
	raw := (*syscall.RawSockaddrUnix)(unsafe.Pointer(&r.Raw))
	name := sa.Name
	n := len(name)
	if n >= len(raw.Path) || n == 0 {
		return syscall.EINVAL
	}
	raw.Len = byte(3 + n) // 2 for Family, Len; 1 for NUL
	raw.Family = syscall.AF_UNIX
	for i := 0; i < n; i++ {
		raw.Path[i] = int8(name[i])
	}
	r.Len = Socklen(raw.Len)
	return nil
}

func (r *RawSockaddr) UpdateDatalink(sa *syscall.SockaddrDatalink) error {
	if sa.Index == 0 {
		return syscall.EINVAL
	}
	raw := (*syscall.RawSockaddrDatalink)(unsafe.Pointer(&r.Raw))
	raw.Len = sa.Len
	raw.Family = syscall.AF_LINK
	raw.Index = sa.Index
	raw.Type = sa.Type
	raw.Nlen = sa.Nlen
	raw.Alen = sa.Alen
	raw.Slen = sa.Slen
	for i := 0; i < len(raw.Data); i++ {
		raw.Data[i] = sa.Data[i]
	}
	r.Len = Socklen(syscall.SizeofSockaddrDatalink)
	return nil
}

func AnyToSockaddr(rsa *syscall.RawSockaddrAny) (syscall.Sockaddr, error) {
	switch rsa.Addr.Family {
	case syscall.AF_LINK:
		pp := (*syscall.RawSockaddrDatalink)(unsafe.Pointer(rsa))
		sa := new(syscall.SockaddrDatalink)
		sa.Len = pp.Len
		sa.Family = pp.Family
		sa.Index = pp.Index
		sa.Type = pp.Type
		sa.Nlen = pp.Nlen
		sa.Alen = pp.Alen
		sa.Slen = pp.Slen
		for i := 0; i < len(sa.Data); i++ {
			sa.Data[i] = pp.Data[i]
		}
		return sa, nil

	case syscall.AF_UNIX:
		pp := (*syscall.RawSockaddrUnix)(unsafe.Pointer(rsa))
		if pp.Len < 3 || pp.Len > syscall.SizeofSockaddrUnix {
			return nil, syscall.EINVAL
		}
		sa := new(syscall.SockaddrUnix)
		n := int(pp.Len) - 3 // subtract leading Family, Len, terminating NUL
		for i := 0; i < n; i++ {
			if pp.Path[i] == 0 {
				// found early NUL; assume Len is overestimating
				n = i
				break
			}
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
