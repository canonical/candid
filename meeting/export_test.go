// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package meeting

// ItemCount reports the number of items stored locally in the Place.
func ItemCount(p *Place) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.items)
}

var (
	ReallyOldExpiryDuration = &reallyOldExpiryDuration
	RunGC                   = (*Place).runGC
)
