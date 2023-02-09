package sock

// this is 99% copied from the following medoium article;
// full credits to jonathan seow
// https://betterprogramming.pub/build-a-tcp-connection-pool-from-scratch-with-go-d7747023fe14

import (
	"errors"
	"net"
	"sync"
	"time"
)

type UDPSocketPool struct {
	host         string
	mu           *sync.Mutex
	idle         map[int64]*UDPSock
	requestChan  chan *sockRequest
	numOpen      int
	maxOpenCount int
	maxIdleCount int
}

// sockRequest wraps a channel to receive a socket
// and a channel to receive an error
type sockRequest struct {
	sockChan chan *UDPSock
	errChan  chan error
}

type UDPSock struct {
	id     int64
	Conn   net.Conn
	dialer *net.Dialer
	cookie *uint64
	pool   *UDPSocketPool
}

func NewUDPPool(host string, count int) (*UDPSocketPool, []uint64, error) {
	pool := &UDPSocketPool{
		host:         host,
		mu:           &sync.Mutex{},
		idle:         make(map[int64]*UDPSock),
		requestChan:  make(chan *sockRequest),
		numOpen:      0,
		maxOpenCount: count,
		maxIdleCount: count,
	}
	go pool.handleConnectionRequest()

	// pre-allocate sockets
	cookies, err := pool.allocate(count)
	if err != nil {
		return nil, nil, err
	}

	return pool, cookies, nil
}

func (p *UDPSocketPool) allocate(count int) ([]uint64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var cookies []uint64
	for i := 0; i < count; i++ {
		sock, err := p.newSocket()
		if err != nil {
			return nil, err
		}
		p.idle[sock.id] = sock
		cookies = append(cookies, *sock.cookie)
	}
	return cookies, nil
}

// Put returns a connection back to the pool
func (p *UDPSocketPool) Put(c *UDPSock) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.maxIdleCount > 0 && p.maxIdleCount > len(p.idle) {
		p.idle[c.id] = c
	} else {
		c.pool.numOpen--
	}
}

// get() retrieves a TCP connection
func (p *UDPSocketPool) Get() (*UDPSock, error) {
	p.mu.Lock()

	// Case 1: Gets a free connection from the pool if any
	numIdle := len(p.idle)
	if numIdle > 0 {
		// Loop map to get one conn
		for _, c := range p.idle {
			// remove from pool
			delete(p.idle, c.id)
			p.mu.Unlock()
			return c, nil
		}
	}

	// Case 2: Queue a connection request
	if p.maxOpenCount > 0 && p.numOpen >= p.maxOpenCount {
		// Create the request
		req := &sockRequest{
			sockChan: make(chan *UDPSock, 1),
			errChan:  make(chan error, 1),
		}

		// Queue the request
		p.requestChan <- req

		p.mu.Unlock()

		// Waits for either
		// 1. Request fulfilled, or
		// 2. An error is returned
		select {
		case udpConn := <-req.sockChan:
			return udpConn, nil
		case err := <-req.errChan:
			return nil, err
		}
	}

	// Case 3: Open a new connection
	p.numOpen++
	p.mu.Unlock()

	sock, err := p.newSocket()
	if err != nil {
		p.mu.Lock()
		p.numOpen--
		p.mu.Unlock()
		return nil, err
	}

	return sock, nil

}

// openNewTcpConnection() creates a new TCP connection at p.host and p.port
func (p *UDPSocketPool) newSocket() (*UDPSock, error) {
	dialer, cookie := CookieDialer()
	conn, err := dialer.Dial("udp", p.host)
	if err != nil {
		return nil, err
	}
	return &UDPSock{
		id:     time.Now().UnixNano(),
		dialer: dialer,
		cookie: cookie,
		Conn:   conn,
		pool:   p,
	}, nil
}

// handleConnectionRequest() listens to the request queue
// and attempts to fulfil any incoming requests
func (p *UDPSocketPool) handleConnectionRequest() {
	for req := range p.requestChan {
		var (
			requestDone = false
			hasTimeout  = false

			// start a 3-second timeout
			timeoutChan = time.After(3 * time.Second)
		)

		for {
			if requestDone || hasTimeout {
				break
			}
			select {
			// request timeout
			case <-timeoutChan:
				hasTimeout = true
				req.errChan <- errors.New("connection request timeout")
			default:

				p.mu.Lock()

				// First, we try to get an idle conn.
				// If fail, we try to open a new conn.
				// If both does not work, we try again in the next loop until timeout.
				numIdle := len(p.idle)
				if numIdle > 0 {
					for _, c := range p.idle {
						delete(p.idle, c.id)
						p.mu.Unlock()
						req.sockChan <- c // give conn
						requestDone = true
						break
					}
				} else if p.maxOpenCount > 0 && p.numOpen < p.maxOpenCount {
					p.numOpen++
					p.mu.Unlock()

					c, err := p.newSocket()
					if err != nil {
						p.mu.Lock()
						p.numOpen--
						p.mu.Unlock()
					} else {
						req.sockChan <- c // give conn
						requestDone = true
					}
				} else {
					p.mu.Unlock()
				}
			}
		}
	}
}
