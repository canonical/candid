package monitoring

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type MeetingMetrics struct {
	meetingCompleted prometheus.Summary
	meetingsExpired  prometheus.Counter
}

func NewMeetingMetrics() *MeetingMetrics {
	meetingCompleted := prometheus.NewSummary(prometheus.SummaryOpts{
		Namespace: "blues_identity",
		Subsystem: "rendevous",
		Name:      "meetings_completed_times",
		Help:      "The time between rendevous creation and its completion.",
	})
	mustRegisterPrometheusCollector(meetingCompleted)
	meetingsExpired := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "blues_identity",
		Subsystem: "rendevous",
		Name:      "meetings_expired_count",
		Help:      "Count of rendevous which were never completed.",
	})
	mustRegisterPrometheusCollector(meetingsExpired)
	return &MeetingMetrics{
		meetingCompleted: meetingCompleted,
		meetingsExpired:  meetingsExpired,
	}
}

func mustRegisterPrometheusCollector(c prometheus.Collector) {
	err := prometheus.DefaultRegisterer.Register(c)
	if err == nil {
		return
	}
	if _, ok := err.(prometheus.AlreadyRegisteredError); ok {
		return
	}
	panic(err)
}

func (m *MeetingMetrics) RequestCompleted(startTime time.Time) {
	m.meetingCompleted.Observe(float64(time.Since(startTime)) / float64(time.Microsecond))
}

func (m *MeetingMetrics) RequestsExpired(count int) {
	m.meetingsExpired.Add(float64(count))
}
