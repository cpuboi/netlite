package tools

import (
	"fmt"
	"os"
)

func ErrCheck(err error) {
	if err != nil {
		//panic(err)
		fmt.Fprintf(os.Stderr, "Error: %s\n", string(err.Error()))
		os.Exit(1)
	}
}
