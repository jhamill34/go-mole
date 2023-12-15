package tunnels

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

const (
	socksVersion = uint8(5)

	authNone            = uint8(0)
	noAcceptableMethods = uint8(255)

	cmdConnect = uint8(1)

	addrTypeIPv4       = uint8(1)
	addrTypeDomainName = uint8(3)

	addrTypeIPv6 = uint8(4)

	repSuccess                 = uint8(0)
	repNetworkUnreachable      = uint8(3)
	repHostUnreachable         = uint8(4)
	repConnectionRefused       = uint8(5)
	repAddressTypeNotSupported = uint8(8)
)

type SocksTunnel struct {
	bastionService BastionService
	keyProvider    KeyProvider
	proxyPort      int

	listener  net.Listener
	sshConfig ssh.ClientConfig
	quit      chan struct{}
	wg        sync.WaitGroup
}

func NewSocksTunnel(
	bastionService BastionService,
	keyProvider KeyProvider,
	proxyPort int,
) *SocksTunnel {
	return &SocksTunnel{
		bastionService: bastionService,
		keyProvider:    keyProvider,
		proxyPort:      proxyPort,
		quit:           make(chan struct{}),
	}
}

func (self *SocksTunnel) Start(ctx context.Context) {
	log.Printf("Starting ssh tunnel")
	bastion, err := self.bastionService.GetBastion(ctx)
	if err != nil {
		panic(err)
	}

	pub, priv := self.keyProvider.RetireveKey()
	self.bastionService.PushKey(ctx, bastion, string(pub))

	signer, err := ssh.ParsePrivateKey(priv)
	if err != nil {
		panic(err)
	}
	self.sshConfig = ssh.ClientConfig{
		User: bastion.User,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", self.proxyPort))
	if err != nil {
		panic(err)
	}

	log.Printf("Listening on localhost:%d", self.proxyPort)
	self.listener = listener

	self.wg.Add(1)
	go self.listen(bastion)
}

func (self *SocksTunnel) Stop() {
	close(self.quit)
	self.listener.Close()

	log.Printf("Waiting for socks clients to close")
	self.wg.Wait()
}

func (self *SocksTunnel) listen(bastion *BastionEntity) {
	defer self.wg.Done()

	for {
		conn, err := self.listener.Accept()
		if err != nil {
			select {
			case <-self.quit:
				log.Printf("Closing socks listener")
				return
			default:
				panic(err)
			}
		} else {
			log.Printf("Accepted connection from %s", conn.RemoteAddr())
			go self.handleConnection(conn, bastion)
		}
	}
}

func (self *SocksTunnel) handleConnection(conn net.Conn, bastion *BastionEntity) {
	defer conn.Close()

	reader := bufio.NewReader(conn)

	var err error

	err = checkVersion(reader)
	if err != nil {
		panic(err)
	}

	err = authenticate(reader, conn)
	if err != nil {
		panic(err)
	}

	req, err := request(reader)
	if err != nil {
		if err == unrecognizedAddrType {
			sendReply(conn, repAddressTypeNotSupported, nil)
		}

		panic(err)
	}

	self.handleRequest(&req, conn, bastion)
}

func checkVersion(r *bufio.Reader) error {
	version := []byte{0}
	if _, err := r.Read(version); err != nil {
		return err
	}

	if version[0] != socksVersion {
		return errors.New("invalid socks version")
	}

	return nil
}

func authenticate(r *bufio.Reader, w io.Writer) error {
	nmethods := []byte{0}
	if _, err := r.Read(nmethods); err != nil {
		panic(err)
	}

	methods := make([]byte, nmethods[0])
	if _, err := r.Read(methods); err != nil {
		panic(err)
	}

	for _, method := range methods {
		if method == authNone {
			w.Write([]byte{socksVersion, authNone})
			return nil
		}
	}

	w.Write([]byte{socksVersion, noAcceptableMethods})
	return errors.New("no acceptable methods")
}

type Request struct {
	reader  *bufio.Reader
	cmd     uint8
	address AddressData
}

func request(r *bufio.Reader) (req Request, err error) {
	// version, cmd, reserved
	header := []byte{0, 0, 0}
	if _, err := io.ReadAtLeast(r, header, 3); err != nil {
		return req, err
	}

	if header[0] != socksVersion {
		return req, errors.New("invalid socks version")
	}
	req.cmd = header[1]

	addr, err := address(r)
	if err != nil {
		return req, err
	}
	req.address = addr
	req.reader = r

	return req, nil
}

type AddressData struct {
	addrType byte
	addr     []byte
	port     []byte
}

var unrecognizedAddrType = errors.New("unrecognized address type")

func address(r *bufio.Reader) (addrData AddressData, err error) {
	addrType := []byte{0}
	if _, err := r.Read(addrType); err != nil {
		return addrData, err
	}

	addrData.addrType = addrType[0]

	switch addrType[0] {
	case addrTypeIPv4:
		addr := make([]byte, 4)
		if _, err := r.Read(addr); err != nil {
			return addrData, err
		}

		addrData.addr = addr
	case addrTypeDomainName:
		domainLen := []byte{0}
		if _, err := r.Read(domainLen); err != nil {
			return addrData, err
		}
		domain := make([]byte, domainLen[0])
		if _, err := r.Read(domain); err != nil {
			return addrData, err
		}

		addrData.addr = domain
	case addrTypeIPv6:
		addr := make([]byte, 16)
		if _, err := r.Read(addr); err != nil {
			return addrData, err
		}

		addrData.addr = addr
	default:
		return addrData, unrecognizedAddrType
	}

	port := make([]byte, 2)
	if _, err := r.Read(port); err != nil {
		return addrData, err
	}
	addrData.port = port

	return addrData, nil
}

func (self *SocksTunnel) handleRequest(req *Request, w io.Writer, bastion *BastionEntity) {
	switch req.cmd {
	case cmdConnect:
		self.handleConnect(req, w, bastion)
	default:
		log.Fatal("invalid command")
	}
}

func (self *SocksTunnel) handleConnect(req *Request, w io.Writer, bastion *BastionEntity) {
	var ip net.IP

	if req.address.addrType == addrTypeIPv4 || req.address.addrType == addrTypeIPv6 {
		ip = net.IP(req.address.addr)
	} else {
		ipAddr, err := net.ResolveIPAddr("ip", string(req.address.addr))

		if err != nil {
			sendReply(w, repHostUnreachable, nil)
			panic(err)
		}

		ip = ipAddr.IP
	}

	var port uint16
	port = uint16(req.address.port[0])<<8 | uint16(req.address.port[1])

	sshClient, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", bastion.IP), &self.sshConfig)
	if err != nil {
		panic(err)
	}
	defer sshClient.Close()

	conn, err := sshClient.Dial("tcp", fmt.Sprintf("%s:%d", ip.String(), port))
	if err != nil {
		msg := err.Error()
		resp := repHostUnreachable
		if strings.Contains(msg, "refused") {
			resp = repConnectionRefused
		} else if strings.Contains(msg, "network is unreachable") {
			resp = repNetworkUnreachable
		}

		if err := sendReply(w, resp, nil); err != nil {
			panic(err)
		}

		panic(err)
	}
	defer conn.Close()

	local := conn.LocalAddr().(*net.TCPAddr)
	var bind AddressData
	if local.IP.To4() != nil {
		bind.addrType = addrTypeIPv4
		bind.addr = []byte(local.IP.To4())
	} else if local.IP.To16() != nil {
		bind.addrType = addrTypeIPv6
		bind.addr = []byte(local.IP.To16())
	}
	bind.port = []byte{uint8(local.Port >> 8), uint8(local.Port & 0xff)}

	if err := sendReply(w, repSuccess, &bind); err != nil {
		panic(err)
	}

	self.wg.Add(2)

	go self.proxy(req.reader, conn)
	go self.proxy(conn, w)

	<-self.quit
}

func (self *SocksTunnel) proxy(r io.Reader, w io.Writer) error {
	defer self.wg.Done()

	_, err := io.Copy(w, r)
	if err != nil {
		return err
	}

	return nil
}

func sendReply(w io.Writer, reply uint8, addr *AddressData) error {
	w.Write([]byte{socksVersion, reply, 0})

	if addr == nil {
		w.Write([]byte{addrTypeIPv4})
		w.Write([]byte{0, 0, 0, 0})
		w.Write([]byte{0, 0})
	} else {
		switch addr.addrType {
		case addrTypeIPv4:
			w.Write([]byte{addrTypeIPv4})
			w.Write(addr.addr)
		case addrTypeDomainName:
			w.Write([]byte{addrTypeDomainName, uint8(len(addr.addr))})
			w.Write(addr.addr)
		case addrTypeIPv6:
			w.Write([]byte{addrTypeIPv6})
			w.Write(addr.addr)
		default:
			return errors.New("invalid address type")
		}
	}

	w.Write([]byte{addr.port[0], addr.port[1]})

	return nil
}

