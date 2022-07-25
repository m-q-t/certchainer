package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/m-q-t/certchainer/pkg/chainer"
)

var (
	urlFlag             = flag.String("url", "", "url to grab the certificate chain for")
	followRedirectsFlag = flag.Bool("follow-redirects", false, "follow HTTP redirects (default: FALSE)")
)

func main() {
	flag.Parse()

	if *urlFlag == "" {
		flag.Usage()
		os.Exit(1)
	}

	certificateChain := *chainer.GrabCertChain(*urlFlag, *followRedirectsFlag)
	if certificateChainMarshalled, err := json.Marshal(certificateChain); err == nil {
		fmt.Println(string(certificateChainMarshalled))
	} else {
		log.Printf("Error occured when marshalling result: %s\n", err)
	}
}
