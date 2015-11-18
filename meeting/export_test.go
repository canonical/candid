// Copyright 2015 Canonical Ltd.

package meeting

// ItemCount reports the number of items stored locally in the Place.
func ItemCount(srv *Server) int {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	return len(srv.items)
}
