package http

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io/ioutil"
	"sync"
	"time"

	"github.com/golang/glog"
)

const TICKET_SEED_RELOAD_SECS = time.Second * 3600

type TicketSeeds struct {
	Current []string `json:"current"`
	New     []string `json:"new"`
	Old     []string `json:"old"`
}

type TicketSeedsReloader struct {
	seedsPath string
	tlsConfig *tls.Config
	timer     *time.Timer
}

func NewTicketSeedsReloader(seedsPath string, tlsConfig *tls.Config) (*TicketSeedsReloader, error) {
	self := &TicketSeedsReloader{seedsPath, tlsConfig, nil}
	if err := self.maybeReload(); err != nil {
		return nil, err
	}
	go func() {
		var wg sync.WaitGroup

		for {
			wg.Add(1)
			self.timer = time.AfterFunc(TICKET_SEED_RELOAD_SECS, func() {
				if err := self.maybeReload(); err != nil {
					glog.Errorf("Unable to reload ticket seeds: %v", err)
				} else {
					glog.Info("Ticket seeds successfully reloaded")
				}
				wg.Done()
			})
			wg.Wait()
		}
	}()
	return self, nil
}

func (self *TicketSeedsReloader) Stop() {
	if self.timer != nil {
		self.timer.Stop()
	}
}

func (self *TicketSeedsReloader) maybeReload() error {
	data, err := ioutil.ReadFile(self.seedsPath)
	if err != nil {
		return err
	}

	var ticketSeeds TicketSeeds
	if err := json.Unmarshal(data, &ticketSeeds); err != nil {
		return err
	}
	if len(ticketSeeds.Current) == 0 {
		return errors.New("Current ticket seeds empty")
	}
	if len(ticketSeeds.Old) == 0 {
		return errors.New("Old ticket seeds empty")
	}
	if len(ticketSeeds.New) == 0 {
		return errors.New("New ticket seeds empty")
	}

	keys := self.seedsToKeys(&ticketSeeds)
	self.tlsConfig.SetSessionTicketKeys(keys)

	return nil
}

func (self *TicketSeedsReloader) seedsToKeys(ticketSeeds *TicketSeeds) [][sha256.Size]byte {
	seedsList := append(ticketSeeds.Current, ticketSeeds.Old...)
	seedsList = append(seedsList, ticketSeeds.New...)

	keys := [][sha256.Size]byte{}
	for _, seed := range seedsList {
		key := sha256.Sum256([]byte(seed))
		keys = append(keys, key)
	}
	return keys
}
