package tunnels

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
)

type SshTunnel struct {
	bastionService BastionService
	keyProvider    KeyProvider
	destination    EndpointProvider
	localPort      int

	listener net.Listener
	sshConn  *ssh.Client
	quit     chan struct{}
	wg       sync.WaitGroup
}

func NewSshTunnel(
	bastionService BastionService,
	keyProvider KeyProvider,
	destination EndpointProvider,
	localPort int,
) *SshTunnel {
	return &SshTunnel{
		bastionService: bastionService,
		keyProvider:    keyProvider,
		destination:    destination,
		localPort:      localPort,
		quit:           make(chan struct{}),
	}
}

func (self *SshTunnel) Start(ctx context.Context) {
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
	sshConf := ssh.ClientConfig{
		User: bastion.User,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
	}

	conn, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", bastion.IP), &sshConf)
	if err != nil {
		panic(err)
	}
	log.Printf("Established ssh connection to %s", bastion.IP)
	self.sshConn = conn

	destination, err := self.destination.GetEndpoint(ctx)
	if err != nil {
		panic(err)
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", self.localPort))
	if err != nil {
		panic(err)
	}
	self.listener = listener

	log.Printf("Listening on localhost:%d", self.localPort)
	self.wg.Add(1)
	go self.listen(bastion, destination.String())
}

func (self *SshTunnel) Stop() {
	close(self.quit)
	self.listener.Close()
	self.sshConn.Close()

	log.Printf("Waiting connections to close")
	self.wg.Wait()
}

func (self *SshTunnel) listen(
	bastion *BastionEntity,
	destination string,
) {
	defer self.wg.Done()

	for {
		conn, err := self.listener.Accept()
		if err != nil {
			select {
			case <-self.quit:
				log.Printf("Shutting down ssh tunnel")
				return
			default:
				panic(err)
			}
		} else {
			log.Printf("Accepted connection from %s", conn.RemoteAddr())
			go self.forward(conn, bastion, destination)
		}
	}
}

func (self *SshTunnel) forward(
	localConn net.Conn,
	bastion *BastionEntity,
	destination string,
) {
	defer localConn.Close()

	remoteConn, err := self.sshConn.Dial("tcp", destination)
	if err != nil {
		panic(err)
	}
	log.Printf("Established connection to %s", destination)
	defer remoteConn.Close()

	self.wg.Add(2)
	go self.copyConn(localConn, remoteConn)
	go self.copyConn(remoteConn, localConn)

	<-self.quit
}

func (self *SshTunnel) copyConn(dst, src net.Conn) {
	defer self.wg.Done()

	_, err := io.Copy(dst, src)
	if err != nil {
		log.Printf(
			"Error copying data between %s and %s: %s",
			dst.RemoteAddr(),
			src.RemoteAddr(),
			err,
		)
	}
}
