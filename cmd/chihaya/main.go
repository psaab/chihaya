// Copyright 2015 The Chihaya Authors. All rights reserved.
// Use of this source code is governed by the BSD 2-Clause license,
// which can be found in the LICENSE file.

package main

import (
	"github.com/chihaya/chihaya"
	"github.com/chihaya/chihaya/config"
	"os"
)

func main() {
	config.DefaultConfig.HTTPConfig.TLSKeyPath = os.Getenv("THRIFT_TLS_CL_KEY_PATH")
	config.DefaultConfig.HTTPConfig.TLSCertPath = os.Getenv("THRIFT_TLS_CL_CERT_PATH")
	chihaya.Boot()
}
