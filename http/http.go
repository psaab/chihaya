// Copyright 2015 The Chihaya Authors. All rights reserved.
// Use of this source code is governed by the BSD 2-Clause license,
// which can be found in the LICENSE file.

// Package http implements a BitTorrent tracker over the HTTP protocol as per
// BEP 3.
package http

import (
	"crypto/tls"

	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/julienschmidt/httprouter"
	"github.com/psaab/graceful"
	"github.com/soheilhy/cmux"
	"github.com/valyala/fasthttp/reuseport"

	"github.com/psaab/chihaya/config"
	"github.com/psaab/chihaya/stats"
	"github.com/psaab/chihaya/tracker"
)

// ResponseHandler is an HTTP handler that returns a status code.
type ResponseHandler func(http.ResponseWriter, *http.Request, httprouter.Params) (int, error)

// Server represents an HTTP serving torrent tracker.
type Server struct {
	config   *config.Config
	tracker  *tracker.Tracker
	http     *graceful.Server
	https    *graceful.Server
	stopping bool
}

// makeHandler wraps our ResponseHandlers while timing requests, collecting,
// stats, logging, and handling errors.
func makeHandler(handler ResponseHandler) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		start := time.Now()
		httpCode, err := handler(w, r, p)
		duration := time.Since(start)

		var msg string
		if err != nil {
			msg = err.Error()
		} else if httpCode != http.StatusOK {
			msg = http.StatusText(httpCode)
		}

		if len(msg) > 0 {
			http.Error(w, msg, httpCode)
			stats.RecordEvent(stats.ErroredRequest)
		}

		if len(msg) > 0 || glog.V(2) {
			reqString := r.URL.Path + " " + r.RemoteAddr
			if glog.V(3) {
				reqString = r.URL.RequestURI() + " " + r.RemoteAddr
			}

			if len(msg) > 0 {
				glog.Errorf("[HTTP - %9s] %s (%d - %s)", duration, reqString, httpCode, msg)
			} else {
				glog.Infof("[HTTP - %9s] %s (%d)", duration, reqString, httpCode)
			}
		}

		stats.RecordEvent(stats.HandledRequest)
		stats.RecordTiming(stats.ResponseTime, duration)
	}
}

// newRouter returns a router with all the routes.
func newRouter(s *Server) *httprouter.Router {
	r := httprouter.New()

	r.GET("/announce", makeHandler(s.serveAnnounce))
	r.GET("/check", makeHandler(s.serveCheck))
	r.GET("/scrape", makeHandler(s.serveScrape))

	return r
}

// connState is used by graceful in order to gracefully shutdown. It also
// keeps track of connection stats.
func (s *Server) connState(conn net.Conn, state http.ConnState) {
	var ssl bool

	if gc, ok := conn.(*graceful.LimitListenerConn); ok {
		_, ssl = gc.Conn.(*tls.Conn)
	} else {
		_, ssl = conn.(*tls.Conn)
	}

	switch state {
	case http.StateNew:
		stats.RecordEvent(stats.AcceptedConnection)
		if ssl {
			stats.RecordEvent(stats.AcceptedSSLConnection)
		}

	case http.StateClosed:
		stats.RecordEvent(stats.ClosedConnection)
		if ssl {
			stats.RecordEvent(stats.ClosedSSLConnection)
		}

	case http.StateHijacked:
		panic("connection impossibly hijacked")

	// Ignore the following cases.
	case http.StateActive, http.StateIdle:

	default:
		glog.Errorf("Connection transitioned to unknown state %s (%d)", state, state)
	}
}

func MatchTLS() cmux.Matcher {
	return func(r io.Reader) bool {
		br := bufio.NewReader(&io.LimitedReader{R: r, N: 6})
		b := make([]byte, 6)
		_, err := br.Read(b)
		if err == nil {
			return len(b) >= 6 && b[0] == '\x16' && b[1] == '\x03' &&
				(b[2] == '\x00' || b[2] == '\x01') && b[5] == '\x01'
		}
		return false
	}
}

// Serve runs an HTTP server, blocking until the server has shut down.
func (s *Server) Serve() {
	glog.V(0).Info("Starting HTTP on ", s.config.HTTPConfig.ListenAddr)

	l, err := reuseport.Listen("tcp6", s.config.HTTPConfig.ListenAddr)
	if err != nil {
		panic(err)
	}

	if s.config.HTTPConfig.ListenLimit != 0 {
		glog.V(0).Info("Limiting connections to ", s.config.HTTPConfig.ListenLimit)
		l = graceful.LimitListener(l, s.config.HTTPConfig.ListenLimit)
	}

	// Create a cmux.
	mux := cmux.New(l)
	mux.SetReadTimeout(s.config.HTTPConfig.ReadTimeout.Duration)

	if s.config.HTTPConfig.TLSCertPath != "" && s.config.HTTPConfig.TLSKeyPath != "" {
		glog.V(0).Info("Starting HTTPS on ", s.config.HTTPConfig.ListenAddr)

		kpr, err := s.newKeypairReloader(s.config.HTTPConfig.TLSCertPath, s.config.HTTPConfig.TLSKeyPath)
		if err != nil {
			panic(err)
		}

		tlsCfg := &tls.Config{
			GetCertificate: kpr.GetCertificateFunc(),
		}

		var tsr *TicketSeedsReloader
		if s.config.HTTPConfig.TLSSeedsPath != "" {
			tsr, err = NewTicketSeedsReloader(s.config.HTTPConfig.TLSSeedsPath, tlsCfg)
			if err != nil {
				panic(err)
			}
		}

		s.https = newGraceful(s)
		s.https.SetKeepAlivesEnabled(false)
		s.https.ShutdownInitiated = func() {
			s.stopping = true
			kpr.timer.Stop()
			if tsr != nil {
				tsr.Stop()
			}
		}

		// Create TLS listener.
		httpsListener := tls.NewListener(mux.Match(MatchTLS()), tlsCfg)
		go func() {
			if err := s.https.Serve(httpsListener); err != nil && err != cmux.ErrListenerClosed {
				panic(err)
			}
			glog.Info("HTTPS server shut down cleanly")
		}()
	}

	httpListener := mux.Match(cmux.Any())

	s.http = newGraceful(s)
	s.http.SetKeepAlivesEnabled(false)
	s.http.ShutdownInitiated = func() { s.stopping = true }

	go func() {
		if err := s.http.Serve(httpListener); err != nil && err != cmux.ErrListenerClosed {
			panic(err)
		}
		glog.Info("HTTP server shut down cleanly")
	}()

	if err := mux.Serve(); !strings.Contains(err.Error(), "use of closed network connection") {
		panic(err)
	}
}

// Stop cleanly shuts down the server.
func (s *Server) Stop() {
	if !s.stopping {
		s.http.Stop(s.http.Timeout)
		if s.https != nil {
			s.https.Stop(s.https.Timeout)
		}
	}
}

func newGraceful(s *Server) *graceful.Server {
	return &graceful.Server{
		Timeout:   s.config.HTTPConfig.RequestTimeout.Duration,
		ConnState: s.connState,

		NoSignalHandling: true,
		Server: &http.Server{
			Addr:         s.config.HTTPConfig.ListenAddr,
			Handler:      newRouter(s),
			ReadTimeout:  s.config.HTTPConfig.ReadTimeout.Duration,
			WriteTimeout: s.config.HTTPConfig.WriteTimeout.Duration,
		},
	}
}

// NewServer returns a new HTTP server for a given configuration and tracker.
func NewServer(cfg *config.Config, tkr *tracker.Tracker) *Server {
	return &Server{
		config:  cfg,
		tracker: tkr,
	}
}
