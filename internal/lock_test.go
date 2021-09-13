package internal

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLockFile(t *testing.T) {
	d, err := ioutil.TempDir("", "cookiejar_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(d)
	filename := filepath.Join(d, "lockfile")
	concurrentCount := int64(0)
	var wg sync.WaitGroup
	locker := func() {
		defer wg.Done()
		closer, err := LockFile(filename)
		if err != nil {
			t.Errorf("cannot obtain lock: %v", err)
			return
		}
		x := atomic.AddInt64(&concurrentCount, 1)
		if x > 1 {
			t.Errorf("multiple locks held at one time")
		}
		defer closer.Close()
		time.Sleep(10 * time.Millisecond)
		atomic.AddInt64(&concurrentCount, -1)
	}
	wg.Add(4)
	for i := 0; i < 4; i++ {
		go locker()
	}
	wg.Wait()
	if concurrentCount != 0 {
		t.Errorf("expected no running goroutines left")
	}
}
