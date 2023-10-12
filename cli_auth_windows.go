package jwtauth

import (
	"os"
	"os/signal"
)

func RegisterNotify(c chan<- os.Signal) {
	signal.Notify(c, os.Interrupt, os.Kill)
}
