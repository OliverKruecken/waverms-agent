package agent

import "sync"

// startOrNoop registers key in m with a fresh stop channel if not already
// present, or reports the existing one. Shared by ubus_watch and ubus_listen,
// whose standing-registration goroutines both need the identical "mutex-
// guarded map[key]chan struct{}, dedup-on-start" contract: re-sending a watch
// or listen for a key already present is a cheap no-op rather than starting a
// redundant goroutine, which is what makes the backend's every-report-cycle
// re-dispatch idempotent.
func startOrNoop[K comparable](mu *sync.Mutex, m map[K]chan struct{}, key K) (stop chan struct{}, alreadyRunning bool) {
	mu.Lock()
	defer mu.Unlock()
	if existing, ok := m[key]; ok {
		return existing, true
	}
	stop = make(chan struct{})
	m[key] = stop
	return stop, false
}

// stopKey removes key from m if present and returns its stop channel so the
// caller can close it outside the lock (the caller — handleUbusUnwatch /
// handleUbusUnlisten — is responsible for closing the returned channel when
// found is true).
func stopKey[K comparable](mu *sync.Mutex, m map[K]chan struct{}, key K) (stop chan struct{}, found bool) {
	mu.Lock()
	defer mu.Unlock()
	stop, found = m[key]
	if found {
		delete(m, key)
	}
	return stop, found
}

// cleanupOwnEntry removes key from m only if its current value is still
// stop — guards against a running goroutine's deferred cleanup deleting an
// entry that a later stop/start cycle for the same key has already replaced.
func cleanupOwnEntry[K comparable](mu *sync.Mutex, m map[K]chan struct{}, key K, stop chan struct{}) {
	mu.Lock()
	defer mu.Unlock()
	if m[key] == stop {
		delete(m, key)
	}
}
