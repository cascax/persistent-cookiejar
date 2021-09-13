package internal

import (
	"context"
	"github.com/gofrs/flock"
	"github.com/pkg/errors"
	"io"
	"time"
)

var newCloser = func(lock *flock.Flock) io.Closer {
	return lock
}

// lockFileName returns the name of the lock file associated with
// the given path.
var lockFileName = func(path string) string {
	return path
}

func LockFile(path string) (io.Closer, error) {
	lock := flock.New(lockFileName(path))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := lock.TryLockContext(ctx, 100*time.Microsecond)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, errors.New("try lock timeout")
		}
		return nil, err
	}
	return newCloser(lock), nil
}
