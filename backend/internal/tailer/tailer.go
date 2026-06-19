// Package tailer watches events.jsonl with inotify and fans out new lines
// to the event store and any registered SSE subscribers.
package tailer

import (
	"bufio"
	"bytes"
	"io"
	"log"
	"os"
	"sync"

	"github.com/fsnotify/fsnotify"

	"qks/backend/internal/eventstore"
)

// Subscriber receives raw JSON lines as they arrive.
type Subscriber struct {
	ch chan []byte
	id uint64
}

// Chan returns the channel the subscriber reads from.
func (s *Subscriber) Chan() <-chan []byte { return s.ch }

// Tailer watches a file and pushes new lines into the store and to subscribers.
type Tailer struct {
	path  string
	store *eventstore.Store

	mu     sync.Mutex
	subs   map[uint64]*Subscriber
	nextID uint64
}

// New creates a Tailer. Call Run in a goroutine to start it.
func New(path string, store *eventstore.Store) *Tailer {
	return &Tailer{
		path:  path,
		store: store,
		subs:  make(map[uint64]*Subscriber),
	}
}

// Subscribe registers a new SSE subscriber and returns it.
// The caller must call Unsubscribe when the connection closes.
func (t *Tailer) Subscribe() *Subscriber {
	t.mu.Lock()
	defer t.mu.Unlock()
	id := t.nextID
	t.nextID++
	sub := &Subscriber{ch: make(chan []byte, 64), id: id}
	t.subs[id] = sub
	return sub
}

// Unsubscribe removes and closes a subscriber channel.
func (t *Tailer) Unsubscribe(sub *Subscriber) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.subs, sub.id)
	close(sub.ch)
}

func (t *Tailer) broadcast(line []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, sub := range t.subs {
		select {
		case sub.ch <- line:
		default:
			// Slow consumer: drop rather than block the tailer goroutine.
		}
	}
}

// Run opens the file, reads any existing lines into the store (backfill),
// then watches for new lines until ctx is cancelled.
// It should be started in its own goroutine.
func (t *Tailer) Run(stop <-chan struct{}) {
	// Backfill: read whatever is already in the file.
	if err := t.backfill(); err != nil {
		log.Printf("[TAILER] backfill error: %v", err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalf("[TAILER] cannot create watcher: %v", err)
	}
	defer watcher.Close()

	if err := watcher.Add(t.path); err != nil {
		log.Fatalf("[TAILER] cannot watch %s: %v", t.path, err)
	}

	f, err := os.Open(t.path)
	if err != nil {
		log.Fatalf("[TAILER] cannot open %s: %v", t.path, err)
	}
	defer f.Close()

	// Seek to end so we only read new lines going forward.
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		log.Fatalf("[TAILER] seek: %v", err)
	}

	reader := bufio.NewReader(f)

	for {
		select {
		case <-stop:
			return

		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) {
				t.drain(reader)
			}
			// On rename/remove (log rotation) re-open the file.
			if event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename) {
				f.Close()
				f, err = os.Open(t.path)
				if err != nil {
					log.Printf("[TAILER] re-open after rotation: %v", err)
					continue
				}
				reader = bufio.NewReader(f)
				watcher.Add(t.path)
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("[TAILER] watcher error: %v", err)
		}
	}
}

// drain reads all complete lines currently available from reader.
func (t *Tailer) drain(reader *bufio.Reader) {
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			line = bytes.TrimRight(line, "\r\n")
			if len(line) > 0 {
				t.handleLine(line)
			}
		}
		if err != nil {
			// io.EOF means we've consumed everything available for now.
			return
		}
	}
}

func (t *Tailer) handleLine(line []byte) {
	ev, err := eventstore.ParseLine(line)
	if err != nil {
		log.Printf("[TAILER] parse error: %v (line: %.80s)", err, line)
		return
	}
	t.store.Push(ev)
	t.broadcast(line)
}

// backfill reads all existing lines in the file into the store only
// (no broadcast — subscribers aren't connected yet at startup).
func (t *Tailer) backfill() error {
	f, err := os.Open(t.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		ev, err := eventstore.ParseLine(line)
		if err != nil {
			log.Printf("[TAILER] backfill parse error: %v", err)
			continue
		}
		t.store.Push(ev)
	}
	return scanner.Err()
}
