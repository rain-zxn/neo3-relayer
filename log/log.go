package log

import (
	"github.com/joeqian10/EasyLogger"
	"log"
)

var Log = EasyLogger.NewRotatingEasyLogger(
	"./Logs/Log.log",
	10,
	30,
	30,
	true,
	false,
	log.Ldate|log.Lmicroseconds,
	"",
	true,
)
