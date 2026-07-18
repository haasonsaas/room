package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/haasonsaas/room/internal/semgrepbundle"
)

func main() {
	rules := flag.String("rules", "", "fragment directory")
	output := flag.String("output", "", "generated output file")
	flag.Parse()
	if *rules == "" || *output == "" {
		flag.Usage()
		os.Exit(2)
	}
	data, err := semgrepbundle.Bundle(*rules)
	if err == nil {
		err = semgrepbundle.WriteFile(*output, data)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
