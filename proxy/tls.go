package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/grepplabs/kafka-proxy/config"
	"github.com/klauspost/cpuid"
	"github.com/pkg/errors"
	"golang.org/x/crypto/pkcs12"
)

var (
	defaultCurvePreferences = []tls.CurveID{
		tls.CurveP256,
		tls.X25519,
	}

	supportedCurvesMap = map[string]tls.CurveID{
		"X25519": tls.X25519,
		"P256":   tls.CurveP256,
		"P384":   tls.CurveP384,
		"P521":   tls.CurveP521,
	}

	defaultCiphers = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}

	defaultCiphersNonAESNI = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}
	// https://github.com/mholt/caddy/blob/master/caddytls/config.go
	supportedCiphersMap = map[string]uint16{
		"ECDHE-ECDSA-AES256-GCM-SHA384":      tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		"ECDHE-RSA-AES256-GCM-SHA384":        tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		"ECDHE-ECDSA-AES128-GCM-SHA256":      tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		"ECDHE-RSA-AES128-GCM-SHA256":        tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		"ECDHE-ECDSA-WITH-CHACHA20-POLY1305": tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		"ECDHE-RSA-WITH-CHACHA20-POLY1305":   tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		"ECDHE-RSA-AES256-CBC-SHA":           tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		"ECDHE-RSA-AES128-CBC-SHA":           tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		"ECDHE-ECDSA-AES256-CBC-SHA":         tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		"ECDHE-ECDSA-AES128-CBC-SHA":         tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		"RSA-AES256-CBC-SHA":                 tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		"RSA-AES128-CBC-SHA":                 tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		"ECDHE-RSA-3DES-EDE-CBC-SHA":         tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		"RSA-3DES-EDE-CBC-SHA":               tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	}

	zeroTime = time.Time{}
)

func newTLSListenerConfig(conf *config.Config) (*tls.Config, error) {
	opts := conf.Proxy.TLS

	if opts.ListenerKeyFile == "" || opts.ListenerCertFile == "" {
		return nil, errors.New("Listener key and cert files must not be empty")
	}
	certPEMBlock, err := ioutil.ReadFile(opts.ListenerCertFile)
	if err != nil {
		return nil, err
	}
	keyPEMBlock, err := ioutil.ReadFile(opts.ListenerKeyFile)
	if err != nil {
		return nil, err
	}
	keyPEMBlock, err = decryptPEM(keyPEMBlock, opts.ListenerKeyPassword)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return nil, err
	}
	cipherSuites, err := getCipherSuites(opts.ListenerCipherSuites)
	if err != nil {
		return nil, err
	}
	// for security, ensure TLS_FALLBACK_SCSV is always included first
	if len(cipherSuites) == 0 || cipherSuites[0] != tls.TLS_FALLBACK_SCSV {
		cipherSuites = append([]uint16{tls.TLS_FALLBACK_SCSV}, cipherSuites...)
	}
	curvePreferences, err := getCurvePreferences(opts.ListenerCurvePreferences)
	if err != nil {
		return nil, err
	}

	cfg := &tls.Config{
		Certificates:             []tls.Certificate{cert},
		ClientAuth:               tls.NoClientCert,
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         curvePreferences,
		CipherSuites:             cipherSuites,
	}
	if opts.CAChainCertFile != "" {
		caCertPEMBlock, err := ioutil.ReadFile(opts.CAChainCertFile)
		if err != nil {
			return nil, err
		}
		clientCAs := x509.NewCertPool()
		if ok := clientCAs.AppendCertsFromPEM(caCertPEMBlock); !ok {
			return nil, errors.New("Failed to parse listener root certificate")
		}
		cfg.ClientCAs = clientCAs
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

func getCipherSuites(enabledCipherSuites []string) ([]uint16, error) {
	suites := make([]uint16, 0)
	for _, suite := range enabledCipherSuites {
		cipher, ok := supportedCiphersMap[strings.TrimSpace(suite)]
		if !ok {
			return nil, errors.Errorf("invalid cipher suite '%s' selected", suite)
		}
		suites = append(suites, cipher)
	}
	if len(suites) == 0 {
		return getPreferredDefaultCiphers(), nil
	}
	return suites, nil
}

// getPreferredDefaultCiphers returns an appropriate cipher suite to use, depending on
// the hardware support available for AES-NI.
//
// See https://github.com/mholt/caddy/issues/1674
func getPreferredDefaultCiphers() []uint16 {
	if cpuid.CPU.AesNi() {
		return defaultCiphers
	}

	// Return a cipher suite that prefers ChaCha20
	return defaultCiphersNonAESNI
}

func getCurvePreferences(enabledCurvePreferences []string) ([]tls.CurveID, error) {
	curvePreferences := make([]tls.CurveID, 0)
	for _, curveID := range enabledCurvePreferences {
		curvePreference, ok := supportedCurvesMap[strings.TrimSpace(curveID)]
		if !ok {
			return nil, errors.Errorf("invalid curveID '%s' selected", curveID)
		}
		curvePreferences = append(curvePreferences, curvePreference)
	}
	if len(curvePreferences) == 0 {
		return defaultCurvePreferences, nil
	}
	return curvePreferences, nil
}

func newTLSClientConfigsMap(conf *config.Config) (map[string]*tls.Config, error) {
	// https://blog.cloudflare.com/exposing-go-on-the-internet/
	opts := conf.Kafka.TLS

	var tlsConfigsMap = make(map[string]*tls.Config, 0)

	cfg := &tls.Config{InsecureSkipVerify: opts.InsecureSkipVerify}

	subject := ""

	if opts.ClientCertFile != "" && opts.ClientKeyFile != "" {
		certPEMBlock, err := ioutil.ReadFile(opts.ClientCertFile)
		if err != nil {
			return nil, err
		}
		keyPEMBlock, err := ioutil.ReadFile(opts.ClientKeyFile)
		if err != nil {
			return nil, err
		}
		keyPEMBlock, err = decryptPEM(keyPEMBlock, opts.ClientKeyPassword)
		if err != nil {
			return nil, err
		}
		cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{cert}
		cpb, _ := pem.Decode(certPEMBlock)
		certX509, err := x509.ParseCertificate(cpb.Bytes)
		if err != nil {
			return nil, err
		}
		subject = certX509.Subject.String()
	}

	tlsConfigsMap[subject] = cfg

	if opts.ClientP12Directory != "" {
		p12FilePaths, err := findFiles(opts.ClientP12Directory, "*.p12")
		if err != nil {
			return nil, err
		}
		for _, p12FilePath := range p12FilePaths {
			cfg := &tls.Config{InsecureSkipVerify: opts.InsecureSkipVerify}
			p12Data, err := ioutil.ReadFile(p12FilePath)
			if err != nil {
				return nil, err
			}
			blocks, err := pkcs12.ToPEM(p12Data, opts.ClientP12Password)
			if err != nil {
				return nil, err
			}

			var pemData []byte
			for _, b := range blocks {
				pemData = append(pemData, pem.EncodeToMemory(b)...)
			}
			x509KeyPair, err := tls.X509KeyPair(pemData, pemData)
			if err != nil {
				return nil, err
			}
			cfg.Certificates = []tls.Certificate{x509KeyPair}
			certX509, err := x509.ParseCertificate(x509KeyPair.Certificate[0])
			if err != nil {
				return nil, err
			}
			tlsConfigsMap[certX509.Subject.String()] = cfg
		}
	}

	if opts.CAChainCertFile != "" {
		caCertPEMBlock, err := ioutil.ReadFile(opts.CAChainCertFile)
		if err != nil {
			return nil, err
		}
		rootCAs := x509.NewCertPool()
		if ok := rootCAs.AppendCertsFromPEM(caCertPEMBlock); !ok {
			return nil, errors.New("Failed to parse client root certificate")
		}
		for _, cfg := range tlsConfigsMap {
			cfg.RootCAs = rootCAs
		}
	}

	return tlsConfigsMap, nil
}

func decryptPEM(pemData []byte, password string) ([]byte, error) {

	keyBlock, _ := pem.Decode(pemData)
	if keyBlock == nil {
		return nil, errors.New("Failed to parse PEM")
	}
	if x509.IsEncryptedPEMBlock(keyBlock) {
		if password == "" {
			return nil, errors.New("PEM is encrypted, but password is empty")
		}
		key, err := x509.DecryptPEMBlock(keyBlock, []byte(password))
		if err != nil {
			return nil, err
		}
		block := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: key,
		}
		return pem.EncodeToMemory(block), nil
	}
	return pemData, nil
}

func parseCertificate(certFile string) (*x509.Certificate, error) {

	content, readErr := ioutil.ReadFile(certFile)

	if readErr != nil {
		return nil, errors.Errorf("Failed to read file from location '%s'", certFile)
	}

	block, _ := pem.Decode(content)

	cert, parseErr := x509.ParseCertificate(block.Bytes)

	if parseErr != nil {
		return nil, errors.Errorf("Failed to parse certificate file from location '%s'", certFile)
	}

	return cert, nil
}

func handshakeAsTLSAndValidateClientCert(conn net.Conn, expectedCert *x509.Certificate, handshakeTimeout time.Duration) error {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return errors.New("Unable to cast connection to TLS when validating client cert")
	}

	err := handshakeTLSConn(tlsConn, handshakeTimeout)
	if err != nil {
		return err
	}

	actualClientCert := filterClientCertificate(tlsConn.ConnectionState().PeerCertificates)

	result := validateClientCert(actualClientCert, expectedCert)

	return result
}

func handshakeTLSConn(tlsConn *tls.Conn, timeout time.Duration) error {
	err := tlsConn.SetDeadline(time.Now().Add(timeout))
	if err != nil {
		return errors.Errorf("Failed to set deadline with handshake timeout in seconds %f on connection: %v", timeout.Seconds(), err)
	}

	err = tlsConn.Handshake()
	if err != nil {
		return errors.Errorf("TLS handshake failed when exchanging client certificates: %v", err)
	}

	err = tlsConn.SetDeadline(zeroTime)
	if err != nil {
		return errors.Errorf("Failed to reset deadline on connection: %v", err)
	}

	return err
}

func filterClientCertificate(peerCertificates []*x509.Certificate) *x509.Certificate {
	for _, v := range peerCertificates {
		if !v.IsCA {
			return v
		}
	}
	return nil
}

func validateClientCert(actualClientCert *x509.Certificate, expectedCert *x509.Certificate) error {
	if actualClientCert == nil {
		return errors.New("Client cert not found in TLS connection")
	}

	if !actualClientCert.Equal(expectedCert) {
		return errors.New("Client cert sent by proxy client does not match brokers client cert (tls-client-cert-file)")
	}
	return nil
}

func findFiles(root, pattern string) ([]string, error) {
	var matches []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if matched, err := filepath.Match(pattern, filepath.Base(path)); err != nil {
			return err
		} else if matched {
			matches = append(matches, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return matches, nil
}
