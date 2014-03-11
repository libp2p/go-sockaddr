package sockaddr

import (
	"syscall"
)

type Socklen uint

type RawSockaddr struct {
	Raw syscall.RawSockaddrAny
	Len Socklen
}

func NewRawSockaddr(s *syscall.Sockaddr) (*RawSockaddr, error) {
	r := new(RawSockaddr)
	err := r.Update(s)
	return r, err
}
