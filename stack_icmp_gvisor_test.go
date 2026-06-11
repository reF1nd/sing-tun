//go:build with_gvisor

package tun

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"

	"github.com/stretchr/testify/require"
)

type localICMPTestTun struct {
	Tun
	endpoint *channel.Endpoint
}

func (t *localICMPTestTun) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	return t.endpoint, stack.NICOptions{}, nil
}

func (t *localICMPTestTun) WritePacket(*stack.PacketBuffer) (int, error) {
	panic("unexpected direct TUN write for local Echo or dropped packet")
}

func TestGVisorLocalICMPEchoBeforeFlowRouting(t *testing.T) {
	testLocalICMPEchoBeforeFlowRouting(t, func(t *testing.T, options Options, handler *localICMPTestHandler) func([]byte) []byte {
		endpoint := channel.New(16, 1500, "")
		t.Cleanup(endpoint.Close)
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		gvisor, err := NewGVisor(StackOptions{
			Context: ctx, Tun: &localICMPTestTun{endpoint: endpoint},
			TunOptions: options, Handler: handler,
			UDPTimeout: time.Minute, ICMPTimeout: time.Minute,
		})
		require.NoError(t, err)
		require.NoError(t, gvisor.Start())
		t.Cleanup(func() { require.NoError(t, gvisor.Close()) })
		return func(raw []byte) []byte {
			protocol := header.IPv4ProtocolNumber
			if raw[0]>>4 == 6 {
				protocol = header.IPv6ProtocolNumber
			}
			packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
			endpoint.InjectInbound(protocol, packet)
			packet.DecRef()
			reply := endpoint.Read()
			if reply == nil {
				return nil
			}
			defer reply.DecRef()
			view := reply.ToView()
			defer view.Release()
			return append([]byte(nil), view.AsSlice()...)
		}
	})
}

func TestMixedLocalICMPEchoBeforeFlowRouting(t *testing.T) {
	testLocalICMPEchoBeforeFlowRouting(t, func(t *testing.T, options Options, handler *localICMPTestHandler) func([]byte) []byte {
		stack, err := NewMixed(StackOptions{TunOptions: options, Handler: handler, Tun: &localICMPTestTun{}})
		require.NoError(t, err)
		mixed := stack.(*Mixed)
		mixed.dispatcher = NewForwardDispatcher(handler, nil, nil, 0, 0)
		t.Cleanup(mixed.dispatcher.Close)
		return func(raw []byte) []byte {
			if mixed.processPacket(raw) {
				return raw
			}
			return nil
		}
	})
}
