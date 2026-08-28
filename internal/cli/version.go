package cli

import (
	"fmt"

	"cloudattack-community/internal/version"
)

const Version = version.Current

func runVersion() {
	fmt.Println("cloudattack version", Version)
}
