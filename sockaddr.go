package sockaddr

import (
	"golang.org/x/sys/unix"
	"unsafe"
)

import "C"

// Socklen is a type for the length of a sockaddr.
type Socklen uint

// SockaddrToAny converts a unix.Sockaddr into a unix.RawSockaddrAny
// The implementation is platform dependent.
func SockaddrToAny(sa unix.Sockaddr) (*unix.RawSockaddrAny, Socklen, error) {
	return sockaddrToAny(sa)
}

// SockaddrToAny converts a unix.RawSockaddrAny into a unix.Sockaddr
// The implementation is platform dependent.
func AnyToSockaddr(rsa *unix.RawSockaddrAny) (unix.Sockaddr, error) {
	return anyToSockaddr(rsa)
}

// AnyToCAny casts a *RawSockaddrAny to a *C.struct_sockaddr_any
func AnyToCAny(a *unix.RawSockaddrAny) *C.struct_sockaddr_any {
	return (*C.struct_sockaddr_any)(unsafe.Pointer(a))
}

// CAnyToAny casts a *C.struct_sockaddr_any to a *RawSockaddrAny
func CAnyToAny(a *C.struct_sockaddr_any) *unix.RawSockaddrAny {
	return (*unix.RawSockaddrAny)(unsafe.Pointer(a))
}
