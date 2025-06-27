package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

type ProxyServer struct {
	conf   *Conf
	logger ILogger
}

func NewProxyServer(conf *Conf, logger ILogger) *ProxyServer {
	return &ProxyServer{
		conf:   conf,
		logger: logger,
	}
}
func (p *ProxyServer) Start() error {
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", p.conf.Proxy.Port))
	if err != nil {
		return err
	}
	defer l.Close()
	p.logger.Info("Proxy server started successfully on port:", p.conf.Proxy.Port)
	for {
		conn, err := l.Accept()

		if err != nil {
			p.logger.Error("Failed to accept connection", err)
			continue
		}
		go p.handleConn(conn)
	}
}
func (p *ProxyServer) handleConn(conn net.Conn) {
	defer conn.Close()

	fmt.Println("New connection from:", conn.RemoteAddr())

	bufReader := bufio.NewReader(conn)

	clientHello, err := readClientHello(bufReader)
	if err != nil {
		p.logger.Error("Failed to read ClientHello", err)
		return
	}

	sni, err := p.extractSNIFromClientHello(clientHello)
	if err != nil {
		p.logger.Error("Failed to extract SNI from client hello", err)
		return
	}

	fmt.Println("SNI:", sni)
}
func readClientHello(r *bufio.Reader) ([]byte, error) {
	header := make([]byte, 5)

	// Step 1: Read the TLS record header
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("failed to read TLS header: %w", err)
	}

	if header[0] != 0x16 {
		return nil, fmt.Errorf("not a TLS handshake")
	}

	length := int(binary.BigEndian.Uint16(header[3:5]))

	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("failed to read TLS body: %w", err)
	}

	return append(header, body...), nil
}
func (p *ProxyServer) extractSNIFromClientHello(data []byte) (string, error) {
	if len(data) < 5 || data[0] != 0x16 {
		return "", fmt.Errorf("not TLS handshake")
	}

	handshakeLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+handshakeLen {
		return "", fmt.Errorf("incomplete TLS record")
	}

	offset := 5 + 38 // handshake header + random + sessionID length

	if len(data) < offset+1 {
		return "", fmt.Errorf("data too short for session ID length")
	}
	sessionIDLen := int(data[43])
	offset += 1 + sessionIDLen

	if len(data) < offset+2 {
		return "", fmt.Errorf("data too short for cipher suites length")
	}
	csLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2 + csLen

	if len(data) < offset+1 {
		return "", fmt.Errorf("data too short for compression methods length")
	}
	compLen := int(data[offset])
	offset += 1 + compLen

	if offset+2 > len(data) {
		return "", fmt.Errorf("no extensions present")
	}

	extLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	end := offset + extLen

	for offset+4 <= end {
		if offset+4 > len(data) {
			break
		}
		extType := binary.BigEndian.Uint16(data[offset : offset+2])
		extSize := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4

		if extType == 0x00 { // SNI extension
			if extSize < 5 {
				return "", fmt.Errorf("SNI extension too short")
			}

			serverNameListLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
			if offset+2+serverNameListLen > len(data) {
				return "", fmt.Errorf("incomplete ServerNameList")
			}

			nameType := data[offset+2]
			if nameType != 0x00 {
				return "", fmt.Errorf("unsupported name type: %d", nameType)
			}

			nameLen := int(binary.BigEndian.Uint16(data[offset+3 : offset+5]))
			if offset+5+nameLen > len(data) {
				return "", fmt.Errorf("incomplete SNI name")
			}

			sni := string(data[offset+5 : offset+5+nameLen])
			return sni, nil
		}
		offset += extSize
	}
	return "", fmt.Errorf("no SNI found")
}
