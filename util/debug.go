package util

import (
	"flag"
	"log"
	"os"
)

var debug = true
var output = ""

func init() {
	debug = *flag.Bool("debug", true, "open the log output")
	output = *flag.String("output", "", "output path")

	if output != "" {
		file, e := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_APPEND|os.O_SYNC, os.ModeAppend)
		if e == nil {
			Debug("output to file")
			log.SetOutput(file)
			return
		}
		Debug("default log output")
	}

}

func Debug(v ...interface{}) {
	if debug {
		log.Println(v)
	}
}
