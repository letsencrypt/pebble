package ma

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/emersion/go-message"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-sasl"
	"github.com/letsencrypt/pebble/acme"
	"github.com/letsencrypt/pebble/core"
	"github.com/miekg/dns"
)

const (
	tls = iota
	strattls
	none
)

type MailTaskGet struct {
	address    string
	mailchanel chan *imap.Message
}

type MailFetcher struct {
	log        *log.Logger
	imapserver string
	username   string
	password   string
	tasks      chan *MailTaskGet
	clt        *imap.client
	istls      bool
}

// NewFetcher make new mail fetcher that curaties imap connection. send empty mailbox, it will filled with io.reader
func NewFetcher(address string, log *log.Logger, username string, password string) (*MailFetcher, Error) {
	c := &MailFetcher{
		log:        log,
		imapserver: address,
		username:   username,
		password:   password,
	}
	c.istls = tls
	client, err := client.DialTLS(address, nil)
	if err != nil {
		client, err = client.Dial(address)
		if err != nil {
			return nil, err
		}
		c.istls = none
		if client.SupportStartTLS() {
			client.Starttls(nil)
			c.istls = starttls
		}
	}
	if err = c.Login(username, password); err != nil {
		c.log.Printf("Failed to Login to IMAP server, wrong account?")
	}
	if err == nil {
		c.log.Printf("Connected to remote Imap server")
		mbox, err := c.Select("INBOX", false)
		if err != nil {
			log.Fatal(err)
		}
		c.clt = client
		go c.processTasks()
		return c, nil
	}

	log.Println("Flags for INBOX:", mbox.Flags)
	c.log.Printf("you shouldn't reach here")
	return nil, err
}

func (c *MailFetcher) Fetch(address string) []*io.Reader {
	f := make(chan *imap.Message)
	c.tasks <- MailTaskGet{
		address:    address,
		mailchanel: f,
	}
	var mails []io.Reader
	for i := range f {
		for _, literal := range i.Body {
			mails := append(mails, io.Reader(literal))
		}
	}
	return mails
}

func (c *MailFetcher) processTasks() {
	for task := range c.tasks {
		//Can't spawn goroutine here as imap client isn't safe to use concurrently
		//test if connection is alive
		if c.clt.State() == imap.LogoutState {
			//we are offline, connect again.
			if c.istls == tls {
				c.clt = client.DialTLS(c.imapserver, nil)
			} else {
				c.clt = client.Dial(c.imapserver)
				if c.istls == starttls {
					c.clt.Starttls()
				}
			}
			c.clt.Login(c.username, c.password)
			c.clt.Select("INBOX", false)
		}
		//now get ACME related mail from challenge sender
		criteria := imap.NewSearchCriteria()
		criteria.Header.Add("FROM", task.address)
		criteria.Header.Add("SUBJECT", "ACME: ")
		criteria.WithoutFlags = []string{imap.SeenFlag}
		seqs, err := c.client.Search(criteria)
		if err != nil {
			c.log.Printf("mail Search failed server side")
		}
		c.clt.Fetch(seqs, []imap.FetchItem{imap.FetchItem("BODY[]")}, task.mailchanel)
		//we sent all, close
		task.mailchanel.Close()
	}
}
