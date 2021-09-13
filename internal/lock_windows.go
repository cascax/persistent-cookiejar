package internal

import (
	"github.com/gofrs/flock"
	"io"
	"os"
)

type flockCloserWin struct {
	lock *flock.Flock
}

func (f *flockCloserWin) Close() error {
	// close before removing because Windows won't allow us
	// to remove an open file.
	err := f.lock.Close()
	// TODO: The remove operation may cause the next lock error
	_ = os.Remove(f.lock.Path())
	return err
}

func init() {
	newCloser = func(lock *flock.Flock) io.Closer {
		return &flockCloserWin{lock}
	}
	lockFileName = func(path string) string {
		return path + ".lock"
	}
}
