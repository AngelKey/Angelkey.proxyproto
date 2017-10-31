package proxyproto

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	// prefix is the string we look for at the start of a connection
	// to check if this connection is using the proxy protocol
	prefix    = []byte("PROXY ")
	prefixLen = len(prefix)
)

// rewindConn is used to playback bytes we read during probing for the PROXY header
type rewindConn struct {
	net.Conn
	peekBuffer *bytes.Reader
}

func newRewindConn(conn net.Conn, peekBuffer *bytes.Reader) *rewindConn {
	return &rewindConn{
		peekBuffer: peekBuffer,
		Conn:       conn,
	}
}

func (p *rewindConn) Read(target []byte) (int, error) {
	if p.peekBuffer != nil {
		// If we have a peekBuffer around, read as much as we can from it. If we have read everything,
		// this read will trigger EOF and we will fall through to the base connection
		rb, err := p.peekBuffer.Read(target)
		if err == nil {
			return rb, nil
		}
	}
	return p.Conn.Read(target)
}

// Listener is used to wrap an underlying listener,
// whose connections may be using the HAProxy Proxy Protocol (version 1).
// If the connection is using the protocol, the RemoteAddr() will return
// the correct client address.
//
// Optionally define ProxyHeaderTimeout to set a maximum time to
// receive the Proxy Protocol Header. Zero means no timeout.
type Listener struct {
	Listener           net.Listener
	ProxyHeaderTimeout time.Duration
	TLSConfig          *tls.Config
	SrcIPFoundCb       func(net.Addr)
}

// Conn is used to wrap and underlying connection which
// may be speaking the Proxy Protocol. If it is, the RemoteAddr() will
// return the address of the client instead of the proxy address.
type Conn struct {
	conn               net.Conn
	dstAddr            *net.TCPAddr
	srcAddr            *net.TCPAddr
	once               sync.Once
	proxyHeaderTimeout time.Duration
	tlsConfig          *tls.Config
	srcIPFoundCb       func(net.Addr)
}

// Accept waits for and returns the next connection to the listener.
func (p *Listener) Accept() (net.Conn, error) {
	// Get the underlying connection
	conn, err := p.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return NewConn(conn, p.ProxyHeaderTimeout, p.TLSConfig, p.SrcIPFoundCb), nil
}

// Close closes the underlying listener.
func (p *Listener) Close() error {
	return p.Listener.Close()
}

// Addr returns the underlying listener's network address.
func (p *Listener) Addr() net.Addr {
	return p.Listener.Addr()
}

// NewConn is used to wrap a net.Conn that may be speaking
// the proxy protocol into a proxyproto.Conn
func NewConn(conn net.Conn, timeout time.Duration, tlsConfig *tls.Config,
	srcIPFoundCb func(net.Addr)) *Conn {
	pConn := &Conn{
		conn:               conn,
		proxyHeaderTimeout: timeout,
		tlsConfig:          tlsConfig,
		srcIPFoundCb:       srcIPFoundCb,
	}
	return pConn
}

// Read is check for the proxy protocol header when doing
// the initial scan. If there is an error parsing the header,
// it is returned and the socket is closed.
func (p *Conn) Read(target []byte) (int, error) {
	var err error
	p.once.Do(func() { err = p.checkPrefix() })
	if err != nil {
		return 0, err
	}
	return p.conn.Read(target)
}

func (p *Conn) Write(b []byte) (int, error) {
	return p.conn.Write(b)
}

func (p *Conn) Close() error {
	return p.conn.Close()
}

func (p *Conn) LocalAddr() net.Addr {
	return p.conn.LocalAddr()
}

// RemoteAddr returns the address of the client if the proxy
// protocol is being used, otherwise just returns the address of
// the socket peer. If there is an error parsing the header, the
// address of the client is not returned, and the socket is closed.
// Once implication of this is that the call could block if the
// client is slow. Using a Deadline is recommended if this is called
// before Read()
func (p *Conn) RemoteAddr() net.Addr {
	p.once.Do(func() {
		if err := p.checkPrefix(); err != nil && err != io.EOF {
			log.Printf("[ERR] Failed to read proxy prefix: %v", err)
			p.Close()
		}
	})
	if p.srcAddr != nil {
		return p.srcAddr
	}
	return p.conn.RemoteAddr()
}

func (p *Conn) SetDeadline(t time.Time) error {
	return p.conn.SetDeadline(t)
}

func (p *Conn) SetReadDeadline(t time.Time) error {
	return p.conn.SetReadDeadline(t)
}

func (p *Conn) SetWriteDeadline(t time.Time) error {
	return p.conn.SetWriteDeadline(t)
}

func (p *Conn) checkPrefix() (err error) {
	var peekBytes []byte
	var bufReader *bufio.Reader

	if p.proxyHeaderTimeout != 0 {
		readDeadLine := time.Now().Add(p.proxyHeaderTimeout)
		p.conn.SetReadDeadline(readDeadLine)
		defer p.conn.SetReadDeadline(time.Time{})
		defer func() {
			if err == nil {
				conn := p.conn

				// If there are any leftover bytes that we have read, make sure to load them
				// into a rewindConn so we can play them back on the next read
				if len(peekBytes) > 0 || bufReader.Buffered() > 0 {
					// If the buffered reader has bytes left that it read but didn't consume,
					// we need to replay those
					if bufReader.Buffered() > 0 {
						buffered := make([]byte, bufReader.Buffered())
						_, err = bufReader.Read(buffered)
						if err != nil {
							return
						}
						peekBytes = append(peekBytes, buffered...)
					}
					conn = newRewindConn(conn, bytes.NewReader(peekBytes))
				}

				if p.tlsConfig != nil {
					// If we have no error, and a TLS config was specified, treat this conn as a TLS conn
					p.conn = tls.Server(conn, p.tlsConfig)
				} else {
					p.conn = conn
				}
			}
		}()
	}

	// Incrementally check each byte of the prefix
	bufReader = bufio.NewReader(p.conn)
	singleByte := make([]byte, 1)
	for i := 0; i < prefixLen; i++ {
		_, err := bufReader.Read(singleByte)
		if err != nil {
			if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
				return nil
			}
			return err
		}
		peekBytes = append(peekBytes, singleByte[0])

		// Check for a prefix mis-match, quit early. Note that peekBytes will not be set to nil,
		// and so we will be creating a rewindConn from it above.
		if singleByte[0] != prefix[i] {
			return nil
		}
	}

	// Copy out peek bytes and set to nil, we will be reading now and any errors from this
	// point on fail the connection (so we want the bytes to not be read by clients, we are
	// processing the PROXY header now)
	line := make([]byte, len(peekBytes))
	copy(line, peekBytes)
	peekBytes = nil

	// Read the header line
	header, err := bufReader.ReadString('\n')
	if err != nil {
		p.conn.Close()
		return err
	}
	header = string(line[:]) + header

	// Strip the carriage return and new line
	header = header[:len(header)-2]

	// Split on spaces, should be (PROXY <type> <src addr> <dst addr> <src port> <dst port>)
	parts := strings.Split(header, " ")
	if len(parts) != 6 {
		p.conn.Close()
		return fmt.Errorf("Invalid header line: %s", header)
	}

	// Verify the type is known
	switch parts[1] {
	case "TCP4":
	case "TCP6":
	default:
		p.conn.Close()
		return fmt.Errorf("Unhandled address type: %s", parts[1])
	}

	// Parse out the source address
	ip := net.ParseIP(parts[2])
	if ip == nil {
		p.conn.Close()
		return fmt.Errorf("Invalid source ip: %s", parts[2])
	}
	port, err := strconv.Atoi(parts[4])
	if err != nil {
		p.conn.Close()
		return fmt.Errorf("Invalid source port: %s", parts[4])
	}
	p.srcAddr = &net.TCPAddr{IP: ip, Port: port}
	if p.srcIPFoundCb != nil {
		p.srcIPFoundCb(p.srcAddr)
	}

	// Parse out the destination address
	ip = net.ParseIP(parts[3])
	if ip == nil {
		p.conn.Close()
		return fmt.Errorf("Invalid destination ip: %s", parts[3])
	}
	port, err = strconv.Atoi(parts[5])
	if err != nil {
		p.conn.Close()
		return fmt.Errorf("Invalid destination port: %s", parts[5])
	}
	p.dstAddr = &net.TCPAddr{IP: ip, Port: port}

	return nil
}
