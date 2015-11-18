package meeting

// ItemCount reports the number of items stored locally in the Place.
func ItemCount(p *Place) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.items)
}
