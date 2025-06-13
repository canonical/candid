package candidtest

import (
	"os"

	qt "github.com/frankban/quicktest"
	"github.com/juju/loggo"
)

// LogTo configures loggo to log to qt.C for the duration
// of the test. If TEST_LOGGING_CONFIG is set, it
// will be used to configure the logging modules.
//
// When c.Done is called, the loggo configuration will
// be reset.
func LogTo(c *qt.C) {
	cfg := os.Getenv("TEST_LOGGING_CONFIG")
	if cfg == "" {
		cfg = "DEBUG"
	}
	// Don't use the default writer for the test logging, which
	// means we can still get logging output from tests that
	// replace the default writer.
	loggo.ResetLogging()
	err := loggo.RegisterWriter(loggo.DefaultWriterName, discardWriter{})
	c.Assert(err, qt.IsNil)
	err = loggo.RegisterWriter("testlogger", &loggoWriter{c})
	c.Assert(err, qt.IsNil)
	err = loggo.ConfigureLoggers(cfg)
	c.Assert(err, qt.IsNil)
	c.Cleanup(loggo.ResetLogging)
}

type loggoWriter struct {
	c *qt.C
}

func (w *loggoWriter) Write(entry loggo.Entry) {
	w.c.Logf("%s %s %s", entry.Level, entry.Module, entry.Message)
}

type discardWriter struct{}

func (discardWriter) Write(entry loggo.Entry) {
}
