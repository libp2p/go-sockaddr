// sockaddr syscall extensions
package sockaddr

import (
	"syscall"
	"unsafe"
)

/*
type SockaddrInet4 struct {
	Port int
	Addr [4]byte
	raw  RawSockaddrInet4
}
*/

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
	raw.Len = uint(unsafe.Sizeof(sa.raw))
	return nil
}

/*
type SockaddrInet6 struct {
	Port   int
	ZoneId uint32
	Addr   [16]byte
	raw    RawSockaddrInet6
}
*/

func (r *RawSockaddr) UpdateInet6(sa *syscall.SockaddrInet6) error {
	if sa.Port < 0 || sa.Port > 0xFFFF {
		return 0, 0, syscall.EINVAL
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
	raw.Len = uint(unsafe.Sizeof(sa.raw))
	return nil
}

/*
type SockaddrUnix struct {
	Name string
}
*/
func (r *RawSockaddr) UpdateUnix(sa *syscall.SockaddrUnix) error {
	// TODO(brainman): implement SockaddrUnix.sockaddr()
	return syscall.EWINDOWS
}
