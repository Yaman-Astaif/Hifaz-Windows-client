package ipc

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/protocol"
)

// ErrUnavailable means the service could not be reached.
var ErrUnavailable = errors.New("ipc: the Hifaz service is not available")

// Client is the app's connection to the service. It keeps two
// connections: the control connection, opened by Connect and kept while the
// tunnel is up (the service takes the tunnel down when it closes), and a
// query connection for everything else. It is safe for concurrent use.
type Client struct {
	dial func() (io.ReadWriteCloser, error)

	qmu   sync.Mutex
	query io.ReadWriteCloser

	cmu     sync.Mutex
	control io.ReadWriteCloser
}

// NewClient returns a client that opens connections with dial.
func NewClient(dial func() (io.ReadWriteCloser, error)) *Client {
	return &Client{dial: dial}
}

func roundTrip(conn io.ReadWriter, req *Request) (*Response, error) {
	defer req.Wipe()
	if err := Write(conn, req); err != nil {
		return nil, err
	}
	var resp Response
	if err := Read(conn, &resp); err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, resp.Error
	}
	return &resp, nil
}

// ask sends a request on the query connection, dialing (once more after a
// broken connection) as needed. Query requests carry no keys, so sending one
// twice is harmless.
func (c *Client) ask(req Request) (*Response, error) {
	c.qmu.Lock()
	defer c.qmu.Unlock()
	var lastErr error
	for range 2 {
		if c.query == nil {
			conn, err := c.dial()
			if err != nil {
				return nil, unavailable(err)
			}
			c.query = conn
		}
		r := req
		resp, err := roundTrip(c.query, &r)
		var svcErr *Error
		if err == nil || errors.As(err, &svcErr) {
			return resp, err
		}
		c.query.Close()
		c.query, lastErr = nil, err
	}
	return nil, transportFailure(lastErr)
}

// Nonce asks for a nonce for one signed server request.
func (c *Client) Nonce() (string, error) {
	resp, err := c.ask(Request{Op: OpNonce})
	if err != nil {
		return "", err
	}
	return resp.Nonce, nil
}

// Register records the server identity from a signed enrollment answer.
func (c *Client) Register(server, identityKey string, doc protocol.SignedDocument) error {
	_, err := c.ask(Request{Op: OpRegister, Server: server, IdentityKey: identityKey, Document: &doc})
	return err
}

// Forget removes the recorded identity for server.
func (c *Client) Forget(server string) error {
	_, err := c.ask(Request{Op: OpForget, Server: server})
	return err
}

// Status reads the tunnel state.
func (c *Client) Status() (*Status, error) {
	resp, err := c.ask(Request{Op: OpStatus})
	if err != nil {
		return nil, err
	}
	return resp.Status, nil
}

// Connect opens the control connection and brings the tunnel up.
func (c *Client) Connect(server string, doc protocol.SignedDocument, priv, psk protocol.Key) (*Status, error) {
	c.cmu.Lock()
	defer c.cmu.Unlock()
	if c.control != nil { // a previous tunnel: closing it takes it down
		c.control.Close()
		c.control = nil
	}
	conn, err := c.dial()
	if err != nil {
		return nil, unavailable(err)
	}
	req := &Request{Op: OpConnect, Server: server, Document: &doc,
		PrivateKey: append([]byte(nil), priv[:]...), PSK: append([]byte(nil), psk[:]...)}
	resp, err := roundTrip(conn, req)
	if err != nil {
		conn.Close()
		return nil, c.wrap(err)
	}
	c.control = conn
	return resp.Status, nil
}

// Update hands a newer session document to the service.
func (c *Client) Update(doc protocol.SignedDocument) (*Status, error) {
	c.cmu.Lock()
	defer c.cmu.Unlock()
	if c.control == nil {
		return nil, &Error{Code: ErrNotOwner}
	}
	resp, err := roundTrip(c.control, &Request{Op: OpUpdate, Document: &doc})
	if err != nil {
		var svcErr *Error
		if !errors.As(err, &svcErr) { // the connection broke: the tunnel is gone
			c.control.Close()
			c.control = nil
		}
		return nil, c.wrap(err)
	}
	return resp.Status, nil
}

// Disconnect takes the tunnel down and closes the control connection.
func (c *Client) Disconnect() error {
	c.cmu.Lock()
	defer c.cmu.Unlock()
	if c.control == nil {
		return nil
	}
	_, err := roundTrip(c.control, &Request{Op: OpDisconnect})
	c.control.Close() // closing alone also takes the tunnel down
	c.control = nil
	var svcErr *Error
	if errors.As(err, &svcErr) {
		return err
	}
	return nil
}

// Close closes both connections.
func (c *Client) Close() {
	c.cmu.Lock()
	if c.control != nil {
		c.control.Close()
		c.control = nil
	}
	c.cmu.Unlock()
	c.qmu.Lock()
	if c.query != nil {
		c.query.Close()
		c.query = nil
	}
	c.qmu.Unlock()
}

// wrap marks transport failures as ErrUnavailable, with their cause;
// service errors pass.
func (c *Client) wrap(err error) error { return transportFailure(err) }

// unavailable marks a dial failure as ErrUnavailable. A dial error that
// already gives the cause (see Dial) passes unchanged.
func unavailable(err error) error {
	if errors.Is(err, ErrUnavailable) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrUnavailable, err)
}
