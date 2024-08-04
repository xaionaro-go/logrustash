package logrustash

import (
	"bytes"
	"encoding/json"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestLogstashHook(t *testing.T) {
	type Expect struct {
		appName          string
		hookOnlyPrefix   string
		alwaysSentFields logrus.Fields
	}
	tt := []struct {
		expected Expect
		initFunc func() (*Hook, error)
	}{
		{Expect{"bla", "", nil}, func() (*Hook, error) {
			return NewHook("udp", "localhost:9999", "bla")
		}},
		{Expect{"bla_async", "", nil}, func() (*Hook, error) {
			return NewHook("udp", "localhost:9999", "bla_async")
		}},
		{Expect{"bzz", "", nil}, func() (*Hook, error) {
			return NewHook("udp", "localhost:9999", "bzz")
		}},
		{Expect{"bzz_async", "", nil}, func() (*Hook, error) {
			return NewHook("udp", "localhost:9999", "bzz_async")
		}},
		{Expect{"blk", "", logrus.Fields{"id": 1}}, func() (*Hook, error) {
			return NewHookWithFields("udp", "localhost:9999", "blk", logrus.Fields{"id": 1})
		}},
		{Expect{"blk_async", "", logrus.Fields{"id": 1}}, func() (*Hook, error) {
			return NewHookWithFields("udp", "localhost:9999", "blk_async", logrus.Fields{"id": 1})
		}},
		{Expect{"prefix", "-->", logrus.Fields{"id": 1}}, func() (*Hook, error) {
			return NewHookWithFieldsAndPrefix("udp", "localhost:9999", "prefix", logrus.Fields{"id": 1}, "-->")
		}},
		{Expect{"fieldsconn", "", logrus.Fields{"id": 5}}, func() (*Hook, error) {
			return NewHookWithFieldsAndConn("udp", "localhost:9999", "fieldsconn", logrus.Fields{"id": 5})
		}},
		{Expect{"fieldsconn_async", "", logrus.Fields{"id": 5}}, func() (*Hook, error) {
			return NewHookWithFieldsAndConn("udp", "localhost:9999", "fieldsconn_async", logrus.Fields{"id": 5})
		}},
		{Expect{"zz", "~~>", logrus.Fields{"id": "bal"}}, func() (*Hook, error) {
			return NewHookWithFieldsAndConnAndPrefix("udp", "localhost:9999", "zz", logrus.Fields{"id": "bal"}, "~~>")
		}},
		{Expect{"zz_async", "~~>", logrus.Fields{"id": "bal"}}, func() (*Hook, error) {
			return NewHookWithFieldsAndConnAndPrefix("udp", "localhost:9999", "zz_async", logrus.Fields{"id": "bal"}, "~~>")
		}},
	}

	for _, te := range tt {
		h, err := te.initFunc()
		if err != nil {
			t.Error(err)
		}
		if h == nil {
			t.Error("expected hook to be not nil")
			return
		}

		if h.conn != nil {
			t.Error("expected conn to be not nil")
		}
		if h.appName != te.expected.appName {
			t.Errorf("expected appName to be '%s' but got '%s'", te.expected.appName, h.appName)
		}
		if h.alwaysSentFields == nil {
			t.Error("expected alwaysSentFields to be not nil")
		}
		if te.expected.alwaysSentFields != nil && !reflect.DeepEqual(te.expected.alwaysSentFields, h.alwaysSentFields) {
			t.Errorf("expected alwaysSentFields to be '%v' but got '%v'", te.expected.alwaysSentFields, h.alwaysSentFields)
		}
		if h.hookOnlyPrefix != te.expected.hookOnlyPrefix {
			t.Error("expected hookOnlyPrefix to be an empty string")
		}
	}
}

type AddrMock struct {
}

func (a AddrMock) Network() string {
	return ""
}

func (a AddrMock) String() string {
	return ""
}

type ConnMock struct {
	buff *bytes.Buffer
}

func (c ConnMock) Read(b []byte) (int, error) {
	return c.buff.Read(b)
}

func (c ConnMock) Write(b []byte) (int, error) {
	return c.buff.Write(b)
}

func (c ConnMock) Close() error {
	return nil
}

func (c ConnMock) LocalAddr() net.Addr {
	return AddrMock{}
}

func (c ConnMock) RemoteAddr() net.Addr {
	return AddrMock{}
}

func (c ConnMock) SetDeadline(t time.Time) error {
	return nil
}

func (c ConnMock) SetReadDeadline(t time.Time) error {
	return nil
}

func (c ConnMock) SetWriteDeadline(t time.Time) error {
	return nil
}

func TestFire(t *testing.T) {
	conn := ConnMock{buff: bytes.NewBufferString("")}
	hook := &Hook{
		conn:             conn,
		appName:          "fire_test",
		alwaysSentFields: logrus.Fields{"test-name": "fire-test", "->ignore": "haaa", "override": "no"},
		hookOnlyPrefix:   "->",
		fireChannel:      make(chan *logrus.Entry, 10),
	}
	hook.init()
	entry := &logrus.Entry{
		Message: "hello world!",
		Data:    logrus.Fields{"override": "yes"},
		Level:   logrus.DebugLevel,
	}
	if err := hook.Fire(entry); err != nil {
		t.Error(err)
	}
	if err := hook.Flush(time.Second); err != nil {
		t.Error(err)
	}
	var res map[string]string
	if err := json.NewDecoder(conn.buff).Decode(&res); err != nil {
		t.Error(err)
	}
	expected := map[string]string{
		"@timestamp": "0001-01-01T00:00:00Z",
		"@version":   "1",
		"ignore":     "haaa",
		"level":      "debug",
		"message":    "hello world!",
		"override":   "yes",
		"test-name":  "fire-test",
		"type":       "fire_test",
	}
	if !reflect.DeepEqual(expected, res) {
		t.Errorf("expected message to be '%v' but got '%v'", expected, res)
	}
}

func TestLevels(t *testing.T) {
	hook := &Hook{fireChannel: make(chan *logrus.Entry, 10)}
	hook.init()
	expected := []logrus.Level{
		logrus.PanicLevel,
		logrus.FatalLevel,
		logrus.ErrorLevel,
		logrus.WarnLevel,
		logrus.InfoLevel,
		logrus.DebugLevel,
		logrus.TraceLevel,
	}
	res := hook.Levels()
	if !reflect.DeepEqual(expected, res) {
		t.Errorf("expected levels to be '%v' but got '%v'", expected, res)
	}

}

func TestLogstashTimeStampFormat(t *testing.T) {
	conn := ConnMock{buff: bytes.NewBufferString("")}
	hook := &Hook{
		conn:        conn,
		TimeFormat:  time.Kitchen,
		fireChannel: make(chan *logrus.Entry, 10),
	}
	hook.init()
	fTime := time.Date(2009, time.November, 10, 3, 4, 0, 0, time.UTC)
	if err := hook.Fire(&logrus.Entry{Time: fTime}); err != nil {
		t.Errorf("expected fire to not return error: %s", err)
	}
	if err := hook.Flush(time.Second); err != nil {
		t.Error(err)
	}
	var res map[string]string
	if err := json.NewDecoder(conn.buff).Decode(&res); err != nil {
		t.Error(err)
	}
	if value, ok := res["@timestamp"]; !ok {
		t.Error("expected result to have '@timestamp'")
	} else if value != "3:04AM" {
		t.Errorf("expected time to be '%s' but got '%s'", "3:04AM", value)
	}
}
