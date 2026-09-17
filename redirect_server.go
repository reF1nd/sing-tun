//go:build linux

package tun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

type RedirectServer struct {
	ctx                 context.Context
	handler             N.TCPConnectionHandlerEx
	packetHandler       AutoRedirectHandler
	logger              logger.Logger
	listenAddress       netip.Addr
	transparent         bool
	externalTransparent bool
	listenMark          uint32
	listener            *net.TCPListener
	packetConn          *ipv6.PacketConn
	access              sync.Mutex
	connections         map[*net.TCPConn]struct{}
}

func (s *RedirectServer) SetExternalTransparent() {
	s.transparent = true
	s.externalTransparent = true
}

func (s *RedirectServer) ListenerFileDescriptor() (int, error) {
	return control.Conn0(s.listener, func(fd uintptr) (int, error) {
		return unix.Dup(int(fd))
	})
}

func NewRedirectServer(ctx context.Context, handler N.TCPConnectionHandlerEx, logger logger.Logger, listenAddress netip.Addr) *RedirectServer {
	return &RedirectServer{
		ctx:           ctx,
		handler:       handler,
		logger:        logger,
		listenAddress: listenAddress,
		connections:   make(map[*net.TCPConn]struct{}),
	}
}

func (s *RedirectServer) Start() error {
	var listenConfig net.ListenConfig
	// listenConfig.KeepAlive = C.TCPKeepAliveInitial
	listenConfig.KeepAlive = 10 * time.Minute
	if s.transparent && !s.externalTransparent {
		listenConfig.Control = control.Append(func(network string, address string, conn syscall.RawConn) error {
			return control.Raw(conn, func(fd uintptr) error {
				err := syscall.SetsockoptInt(int(fd), syscall.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
				if err != nil {
					return E.Cause(err, "set IPV6_TRANSPARENT")
				}
				return nil
			})
		}, control.RoutingMark(s.listenMark))
	}
	listener, err := listenConfig.Listen(s.ctx, M.NetworkFromNetAddr("tcp", s.listenAddress), M.SocksaddrFrom(s.listenAddress, 0).String())
	if err != nil {
		return err
	}
	tcpListener := listener.(*net.TCPListener)
	if s.packetHandler != nil {
		var conn net.PacketConn
		conn, err = listenConfig.ListenPacket(s.ctx, "udp6", "[::]:0")
		if err != nil {
			tcpListener.Close()
			return err
		}
		packetConn := ipv6.NewPacketConn(conn)
		err = packetConn.SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true)
		if err != nil {
			conn.Close()
			tcpListener.Close()
			return err
		}
		s.packetConn = packetConn
		go s.loopPacketIn()
	}
	s.StartWithListener(tcpListener)
	return nil
}

// StartWithListener takes ownership of an already listening TCP socket. This lets
// a privileged process create the socket without moving connection handling out
// of the process running the redirect server.
func (s *RedirectServer) StartWithListener(listener *net.TCPListener) {
	s.listener = listener
	go s.loopIn()
}

func (s *RedirectServer) Port() uint16 {
	return M.AddrPortFromNet(s.listener.Addr()).Port()
}

func (s *RedirectServer) PacketPort() uint16 {
	return M.AddrPortFromNet(s.packetConn.LocalAddr()).Port()
}

func (s *RedirectServer) Close() error {
	s.access.Lock()
	connections := s.connections
	s.connections = nil
	s.access.Unlock()
	err := s.listener.Close()
	if s.packetConn != nil {
		err = E.Errors(err, s.packetConn.Close())
	}
	for conn := range connections {
		_ = conn.SetLinger(0)
		_ = conn.Close()
	}
	return err
}

func (s *RedirectServer) loopIn() {
	var retryDelay time.Duration
	for {
		conn, err := s.listener.AcceptTCP()
		if err != nil {
			s.access.Lock()
			closed := s.connections == nil
			s.access.Unlock()
			if closed && E.IsClosed(err) {
				return
			}
			var netError net.Error
			//nolint:staticcheck
			if errors.As(err, &netError) && netError.Temporary() {
				if retryDelay == 0 {
					retryDelay = 5 * time.Millisecond
				} else {
					retryDelay *= 2
				}
				if retryDelay > time.Second {
					retryDelay = time.Second
				}
				s.logger.Error("accept: ", err, ": retrying in ", retryDelay)
				time.Sleep(retryDelay)
				continue
			}
			s.listener.Close()
			s.logger.Error("serve error: ", err)
			return
		}
		retryDelay = 0
		// FileListener cannot preserve the ListenConfig across an FD handoff.
		_ = conn.SetKeepAliveConfig(net.KeepAliveConfig{Enable: true, Idle: 10 * time.Minute})
		source := M.SocksaddrFromNet(conn.RemoteAddr()).Unwrap()
		var destination M.Socksaddr
		if s.transparent && !source.IsIPv4() {
			destination = M.SocksaddrFromNet(conn.LocalAddr()).Unwrap()
		} else {
			var originalDestination netip.AddrPort
			originalDestination, err = control.GetOriginalDestination(conn)
			if err != nil {
				_ = conn.SetLinger(0)
				_ = conn.Close()
				s.logger.Error("process redirect connection from ", source, ": invalid connection: ", err)
				continue
			}
			if isDirectRedirectConnection(conn.LocalAddr(), originalDestination) {
				_ = conn.SetLinger(0)
				_ = conn.Close()
				s.logger.Warn("reject direct connection to redirect listener from ", source)
				continue
			}
			destination = M.SocksaddrFromNetIP(originalDestination).Unwrap()
		}
		s.access.Lock()
		if s.connections == nil {
			s.access.Unlock()
			_ = conn.SetLinger(0)
			_ = conn.Close()
			return
		}
		s.connections[conn] = struct{}{}
		s.access.Unlock()
		go s.handler.NewConnectionEx(s.ctx, conn, source, destination, func(error) {
			s.access.Lock()
			delete(s.connections, conn)
			s.access.Unlock()
		})
	}
}

func (s *RedirectServer) loopPacketIn() {
	buffer := make([]byte, 65535)
	for {
		n, controlMessage, source, err := s.packetConn.ReadFrom(buffer)
		if err != nil {
			if !E.IsClosed(err) {
				s.logger.Error(E.Cause(err, "read redirected packet"))
			}
			return
		}
		if controlMessage == nil {
			continue
		}
		s.packetHandler.NewDNSPacket(buffer[:n], M.SocksaddrFromNet(source).Unwrap(), M.SocksaddrFrom(M.AddrFromIP(controlMessage.Dst), 53), &redirectPacketWriter{
			packetConn: s.packetConn,
			source:     source,
			controlMessage: ipv6.ControlMessage{
				Src:     controlMessage.Dst,
				IfIndex: controlMessage.IfIndex,
			},
		})
	}
}

type redirectPacketWriter struct {
	packetConn     *ipv6.PacketConn
	source         net.Addr
	controlMessage ipv6.ControlMessage
}

func (w *redirectPacketWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	_, err := w.packetConn.WriteTo(buffer.Bytes(), &w.controlMessage, w.source)
	return err
}

var _ N.PacketWriter = (*redirectPacketWriter)(nil)
