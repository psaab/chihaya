package http

import (
	"crypto/tls"
	"crypto/x509"

	"sync"
	"time"

	"github.com/golang/glog"
)

type keypairReloader struct {
	certMu     sync.RWMutex
	cert       *tls.Certificate
	certPath   string
	keyPath    string
	timer      *time.Timer
	reloadTime time.Duration
}

func (s *Server) newKeypairReloader(certPath, keyPath string) (*keypairReloader, error) {
	result := &keypairReloader{
		certPath: certPath,
		keyPath:  keyPath,
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	result.cert = &cert
	go func() {
		var wg sync.WaitGroup

		for {
			pCert, err := x509.ParseCertificate(result.cert.Certificate[0])
			if err != nil {
				glog.Errorf("Failed to parse x509 Certificate %v", err)
				result.reloadTime = time.Second * 6 * 3600 // XXX: Configuration for default cert refresh?
			} else {
				result.reloadTime = time.Until(pCert.NotAfter) - (time.Second * 3600)
				if result.reloadTime < 0 {
					result.reloadTime = time.Until(pCert.NotAfter)
				}
			}
			glog.Info("Time until certificate reload: ", result.reloadTime)
			if result.timer == nil {
				result.timer = time.AfterFunc(result.reloadTime, func() {
					if err := result.maybeReload(); err != nil {
						glog.Errorf("Keeping old TLS certificate because the new one could not be loaded: %v", err)
					} else {
						glog.Info("TLS certificate successfully reloaded")
					}
					wg.Done()
				})
				wg.Add(1)
			} else {
				result.timer.Reset(result.reloadTime)
				wg.Add(1)
			}
			wg.Wait()
		}
	}()
	return result, nil
}

func (kpr *keypairReloader) maybeReload() error {
	newCert, err := tls.LoadX509KeyPair(kpr.certPath, kpr.keyPath)
	if err != nil {
		return err
	}
	kpr.certMu.Lock()
	defer kpr.certMu.Unlock()
	kpr.cert = &newCert
	return nil
}

func (kpr *keypairReloader) GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		kpr.certMu.RLock()
		defer kpr.certMu.RUnlock()
		return kpr.cert, nil
	}
}
