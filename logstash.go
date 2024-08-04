package logrustash

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/facebookincubator/go-belt/tool/experimental/errmon"
	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/facebookincubator/go-belt/tool/logger/implementation/stdlib"
	"github.com/sirupsen/logrus"
)

var (
	log logger.Logger = stdlib.Default()
)

// Hook represents a connection to a Logstash instance
type Hook struct {
	sendingLocker            sync.Mutex
	conn                     net.Conn
	protocol                 string
	address                  string
	appName                  string
	alwaysSentFields         logrus.Fields
	hookOnlyPrefix           string
	TimeFormat               string
	fireChannel              chan *logrus.Entry
	WaitUntilBufferFrees     bool
	Timeout                  time.Duration // Timeout for sending message.
	MaxSendRetries           int           // Declares how many times we will try to resend message.
	ReconnectBaseDelay       time.Duration // First reconnect delay.
	ReconnectDelayMultiplier float64       // Base multiplier for delay before reconnect.
	MaxReconnectRetries      int           // Declares how many times we will try to reconnect.
}

// NewHook creates a new hook to a Logstash instance, which listens on
// `protocol`://`address`.
// Logs will be sent asynchronously.
func NewHook(protocol, address, appName string) (*Hook, error) {
	return NewHookWithFields(protocol, address, appName, make(logrus.Fields))
}

// NewHookWithFields creates a new hook to a Logstash instance, which listens on
// `protocol`://`address`. alwaysSentFields will be sent with every log entry.
// Logs will be sent asynchronously.
func NewHookWithFields(
	protocol, address string,
	appName string,
	alwaysSentFields logrus.Fields,
) (*Hook, error) {
	return NewHookWithFieldsAndPrefix(protocol, address, appName, alwaysSentFields, "")
}

// NewHookWithFieldsAndPrefix creates a new hook to a Logstash instance, which listens on
// `protocol`://`address`. alwaysSentFields will be sent with every log entry. prefix is used to select fields to filter.
func NewHookWithFieldsAndPrefix(
	protocol, address string,
	appName string,
	alwaysSentFields logrus.Fields,
	prefix string,
) (*Hook, error) {
	return NewHookWithFieldsAndConnAndPrefix(protocol, address, appName, alwaysSentFields, prefix)
}

// NewHookWithFieldsAndConn creates a new hook to a Logstash instance using the supplied connection.
// Logs will be sent asynchronously.
func NewHookWithFieldsAndConn(
	protocol, address string,
	appName string,
	alwaysSentFields logrus.Fields,
) (*Hook, error) {
	return NewHookWithFieldsAndConnAndPrefix(protocol, address, appName, alwaysSentFields, "")
}

// NewHookWithFieldsAndConnAndPrefix creates a new hook to a Logstash instance using the supplied connection and prefix.
// Logs will be sent asynchronously.
func NewHookWithFieldsAndConnAndPrefix(
	protocol, address string,
	appName string,
	alwaysSentFields logrus.Fields,
	prefix string,
) (*Hook, error) {
	h := &Hook{
		protocol:         protocol,
		address:          address,
		appName:          appName,
		alwaysSentFields: alwaysSentFields,
		hookOnlyPrefix:   prefix,
		fireChannel:      make(chan *logrus.Entry, 65536),
	}
	h.init()
	return h, nil
}

func (h *Hook) init() {
	go func() {
		defer func() { errmon.ObserveRecoverCtx(context.TODO(), recover()) }()
		defer log.Errorf("the fireChannel handler is closed")
		if h.conn == nil {
			h.reconnect()
		}
		for entry := range h.fireChannel {
			if err := h.sendMessage(entry); err != nil {
				log.Errorf("unable to send the message: %v", err)
			}
		}
	}()
}

func (h *Hook) filterHookOnly(entry *logrus.Entry) {
	if h.hookOnlyPrefix == "" {
		return
	}

	for key := range entry.Data {
		if strings.HasPrefix(key, h.hookOnlyPrefix) {
			delete(entry.Data, key)
		}
	}
}

// SetPrefix sets a prefix filter to use in all subsequent logging
func (h *Hook) SetPrefix(prefix string) {
	h.hookOnlyPrefix = prefix
}

// SetField add field with value that will be sent with each message
func (h *Hook) SetField(key string, value interface{}) {
	h.alwaysSentFields[key] = value
}

// SetFields add fields with values that will be sent with each message
func (h *Hook) SetFields(fields logrus.Fields) {
	// Add all the new fields to the 'alwaysSentFields', possibly overwriting existing fields
	for key, value := range fields {
		h.alwaysSentFields[key] = value
	}
}

// Fire send message to logstash.
// In async mode log message will be dropped if message buffer is full.
// If you want wait until message buffer frees – set WaitUntilBufferFrees to true.
func (h *Hook) Fire(entry *logrus.Entry) error {
	select {
	case h.fireChannel <- entry:
	default:
		if h.WaitUntilBufferFrees {
			h.fireChannel <- entry // blocks the goroutine because buffer is full.
			return nil
		}
		log.Errorf("dropped a message")
	}
	return nil
}

func (h *Hook) sendMessage(entry *logrus.Entry) error {
	// Make sure we always clear the hook only fields from the entry
	defer h.filterHookOnly(entry)

	// Add in the alwaysSentFields. We don't override fields that are already set.
	for k, v := range h.alwaysSentFields {
		if _, inMap := entry.Data[k]; !inMap {
			entry.Data[k] = v
		}
	}

	formatter := LogstashFormatter{Type: h.appName}
	if h.TimeFormat != "" {
		formatter.TimestampFormat = h.TimeFormat
	}

	dataBytes, err := formatter.FormatWithPrefix(entry, h.hookOnlyPrefix)
	if err != nil {
		return err
	}

	h.sendingLocker.Lock()
	defer h.sendingLocker.Unlock()
	h.performSend(dataBytes)
	return nil
}

// performSend tries to send data recursively.
// sendRetries is the actual number of attempts to resend message.
func (h *Hook) performSend(data []byte) {
	if h.Timeout > 0 {
		h.conn.SetWriteDeadline(time.Now().Add(h.Timeout))
	}

	delay := time.Millisecond * 10
	for {
		_, err := h.conn.Write(data)
		if err == nil {
			break
		}
		log.Errorf("unable to write: %v", err)
		time.Sleep(delay)
		delay = time.Duration(float64(delay) * 6 / 5)
		if delay > time.Second {
			delay = time.Second
		}
		h.reconnect()
	}
}

func (h *Hook) reconnect() {
	delay := time.Millisecond * 10
	for {
		conn, err := net.Dial(h.protocol, h.address)
		if err == nil {
			h.conn = conn
			return
		}
		log.Errorf("unable to connect to %s://%s: %v", h.protocol, h.address, err)
		time.Sleep(delay)
		delay = time.Duration(float64(delay) * 6 / 5)
		if delay > time.Second {
			delay = time.Second
		}
	}
}

// Levels specifies "active" log levels.
// Log messages with this levels will be sent to logstash.
func (h *Hook) Levels() []logrus.Level {
	return []logrus.Level{
		logrus.PanicLevel,
		logrus.FatalLevel,
		logrus.ErrorLevel,
		logrus.WarnLevel,
		logrus.InfoLevel,
		logrus.DebugLevel,
		logrus.TraceLevel,
	}
}

func (h *Hook) Flush(timeout time.Duration) error {
	expireAt := time.Now().Add(timeout)

	for time.Now().Before(expireAt) {
		h.sendingLocker.Lock()
		h.sendingLocker.Unlock() //lint:ignore SA2001 we are just waiting for lock being released
		if len(h.fireChannel) == 0 {
			return nil
		}
		time.Sleep(time.Millisecond)
	}

	return context.DeadlineExceeded
}
