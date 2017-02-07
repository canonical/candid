package store

import (
	"strings"
	"time"

	"github.com/juju/utils/cache"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/errgo.v1"
	"launchpad.net/lpad"
)

// LaunchpadGroups provides an implementation of ExternalGroupGetter
// that fetches groups from Launchpad and caches the results.
type LaunchpadGroups struct {
	cache   *cache.Cache
	base    lpad.APIBase
	monitor prometheus.Summary
}

// NewLaunchpadGroups returns a new LaunchpadGroups instance
// that uses the given base URL and caches entries for at most the
// given duration.
func NewLaunchpadGroups(base lpad.APIBase, cacheDuration time.Duration) *LaunchpadGroups {
	return &LaunchpadGroups{
		cache: cache.New(cacheDuration),
		base:  base,
		monitor: prometheus.NewSummary(prometheus.SummaryOpts{
			Namespace: "blues_identity",
			Subsystem: "launchpad",
			Name:      "get_launchpad_groups",
			Help:      "The duration of launchpad login, /people, and super_teams_collection_link requests.",
		}),
	}
}

// GetGroups implements ExternalGroupGetter by retrieving the
// the groups from Launchpad if the user is a launchpad user,
// otherwise it returns an empty slice.
func (g *LaunchpadGroups) GetGroups(externalId string) ([]string, error) {
	if !strings.HasPrefix(externalId, "https://login.ubuntu.com/+id/") {
		return nil, nil
	}
	groups, err := g.cache.Get(externalId, func() (interface{}, error) {
		t := time.Now()
		groups, err := g.getLaunchpadGroupsNoCache(externalId)
		g.monitor.Observe(float64(time.Since(t)) / float64(time.Microsecond))
		return groups, err
	})
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return groups.([]string), nil
}

// getLaunchpadGroups tries to fetch the list of teams the user
// belongs to in launchpad. Only public teams are supported.
func (g *LaunchpadGroups) getLaunchpadGroupsNoCache(externalId string) ([]string, error) {
	root, err := lpad.Login(g.base, &lpad.OAuth{Consumer: "blues", Anonymous: true})
	if err != nil {
		return nil, errgo.Notef(err, "cannot connect to launchpad")
	}
	user, err := g.getLaunchpadPersonByOpenID(root, externalId)
	if err != nil {
		return nil, errgo.Notef(err, "cannot find user %s", externalId)
	}
	teams, err := user.Link("super_teams_collection_link").Get(nil)
	if err != nil {
		return nil, errgo.Notef(err, "cannot get team list for launchpad user %q", user.Name())
	}
	groups := make([]string, 0, teams.TotalSize())
	teams.For(func(team *lpad.Value) error {
		groups = append(groups, team.StringField("name"))
		return nil
	})
	return groups, nil
}

func (g *LaunchpadGroups) getLaunchpadPersonByOpenID(root *lpad.Root, externalId string) (*lpad.Person, error) {
	launchpadId := "https://login.launchpad.net/+id/" + strings.TrimPrefix(externalId, "https://login.ubuntu.com/+id/")
	v, err := root.Location("/people").Get(lpad.Params{"ws.op": "getByOpenIDIdentifier", "identifier": launchpadId})
	// TODO if err == lpad.ErrNotFound, return a not found error
	// so that we won't round-trip to launchpad for users that don't exist there.
	if err != nil {
		return nil, errgo.Notef(err, "cannot find user %s", externalId)
	}
	return &lpad.Person{v}, nil
}
