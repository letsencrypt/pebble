package ma

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
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
	"github.com/emersion/go-smtp"
	"github.com/letsencrypt/challtestsrv"
	"github.com/letsencrypt/pebble/acme"
	"github.com/letsencrypt/pebble/core"
	"github.com/miekg/dns"
)

const ()

type MailTaskSend struct {
	Identifier acme.Identifier
	Challenge  *core.Challenge
}

type SenderImpl struct {
	log         *log.Logger
	smtpserver  string
	auth        sasl.Client
	fromaddr    string
	tasks       chan *MailTaskSend
	alwaysValid bool
}

func NewSender(address string, log *log.Logger, username string, password string) *SenderImpl {
	s := *SenderImpl{
		log:      log,
		fromaddr: address,
		auth:     sasl.NewPlainClient("", username, password),
	}
	go s.processTasks()
	return &s
}

// CraftMailforChallenge creates mail reader
func CraftMailforChallenge(ident acme.Identifier, chal *core.Challenge) (bytes.Buffer, error) {
	var b bytes.Buffer
	var h message.Header
	h.SetContentType("text/plain", nil)
	h.SetText("subject", "ACME: "+chal.OutOfBandToken)
	h.SetText("from", chal.Challenge.From)
	h.SetText("to", idnet.Value)
	w, err := message.CreateWriter(&b, h)
	if err != nil {
		log.Fatal(err)
	}
	//fill body of the message
	bodytowrite := "Pebble RFC8823 challenge mail: for testing"
	io.WriteString(w, bodytowrite)
	w.Close()
	return b, nil
	smtp.sendmail
}

// this doesn't do dkim sign, so recieving smtp server should sign message for us.
func (s *SenderImpl) processTasks() {
	for task := range s.tasks {
		//todo: async or reuse connection
		m, err := CraftMailforChallenge(task.Identifier.Value, task.Challenge)
		if err != nil {
			s.log.Printf()
		}
		smtp.Sendmail(s.smtpserver, s.auth, s.fromaddr, task.Identifier.Value, m)
	}
}
