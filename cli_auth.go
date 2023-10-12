//go:build !windows

package jwtauth

import (
	"os"
	"os/signal"
	"syscall"
)

func RegisterNotify(c chan<- os.Signal) {
	signal.Notify(c, os.Interrupt, os.Kill, syscall.SIGTSTP)
}
