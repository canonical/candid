// Copyright 2015 Canonical Ltd.

package meeting

// ItemCount reports the number of items stored locally in the Place.
func ItemCount(p *Place) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.items)
}

var (
	ExpiryDuration          = &expiryDuration
	ReallyOldExpiryDuration = &reallyOldExpiryDuration
	RunGC                   = (*Place).runGC
)

func NewPlaceNoGC(s Store, m Metrics, listenAddr string) (*Place, error) {
	return newPlace(s, m, listenAddr, false)
}
