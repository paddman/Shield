package collector

import (
	"context"
	"errors"
	"log"
	"net"
	"time"
)

type SyslogDatagram struct {
	Payload    string
	RemoteAddr string
	ReceivedAt time.Time
}

func ListenSyslog(ctx context.Context, address string, maxMessageBytes int, logger *log.Logger) (<-chan SyslogDatagram, error) {
	if maxMessageBytes < 1024 || maxMessageBytes > 65507 {
		maxMessageBytes = 65507
	}
	conn, err := net.ListenPacket("udp", address)
	if err != nil {
		return nil, err
	}
	out := make(chan SyslogDatagram, 1024)
	go func() {
		defer close(out)
		defer conn.Close()
		buf := make([]byte, maxMessageBytes)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			n, remote, readErr := conn.ReadFrom(buf)
			if readErr != nil {
				var ne net.Error
				if errors.As(readErr, &ne) && ne.Timeout() {
					select {
					case <-ctx.Done():
						return
					default:
						continue
					}
				}
				if ctx.Err() != nil {
					return
				}
				logger.Printf("syslog listener read error: %v", readErr)
				continue
			}
			msg := SyslogDatagram{
				Payload:    string(append([]byte(nil), buf[:n]...)),
				RemoteAddr: remote.String(),
				ReceivedAt: time.Now().UTC(),
			}
			select {
			case out <- msg:
			case <-ctx.Done():
				return
			default:
				logger.Printf("syslog input queue full; dropping datagram from %s", remote.String())
			}
		}
	}()
	return out, nil
}
