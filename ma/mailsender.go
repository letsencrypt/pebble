package ma

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/emersion/go-message"
	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/letsencrypt/pebble/acme"
)

const ()

type MailTaskSend struct {
	Identifier     acme.Identifier
	OutOfBandToken string
}

type SenderImpl struct {
	log        *log.Logger
	smtpserver string
	auth       sasl.Client
	Fromaddr   string
	Tasks      chan *MailTaskSend
}

func NewSender(log *log.Logger, address string, fromaddr string, username string, password string) *SenderImpl {
	s := &SenderImpl{
		log:        log,
		smtpserver: address,
		Fromaddr:   fromaddr,
		auth:       sasl.NewPlainClient("", username, password),
		Tasks:      make(chan *MailTaskSend, 5),
	}
	go s.processTasks()
	return s
}

// CraftMailforChallenge creates mail reader
func (s *SenderImpl) CraftMailforChallenge(ident acme.Identifier, OutOfBandToken string) (bytes.Buffer, error) {
	var b bytes.Buffer
	var h message.Header
	h.SetContentType("text/plain", nil)
	h.SetText("subject", "ACME: "+OutOfBandToken)
	h.SetText("from", s.Fromaddr)
	h.SetText("to", ident.Value)
	w, err := message.CreateWriter(&b, h)
	if err != nil {
		log.Fatal(err)
	}
	//fill body of the message
	bodytowrite := fmt.Sprintf("Pebble RFC8823 challenge mail: for testing sent %s", time.Now())
	io.WriteString(w, bodytowrite)
	w.Close()
	return b, nil
}

// this doesn't do dkim sign, so recieving smtp server should sign message for us.
func (s *SenderImpl) processTasks() {
	for task := range s.Tasks {
		//todo: async or reuse connection
		m, err := s.CraftMailforChallenge(task.Identifier, task.OutOfBandToken)
		if err != nil {
			s.log.Println(err)
		}
		err = smtp.SendMail(s.smtpserver, s.auth, s.Fromaddr, []string{task.Identifier.Value}, &m)
		if err != nil {
			s.log.Println(err)
		}
	}
}
