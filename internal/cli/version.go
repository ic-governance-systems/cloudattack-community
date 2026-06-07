package cli

import "fmt"

const Version = "0.1.0"

func runVersion() {
	fmt.Println("cloudattack version", Version)
}
