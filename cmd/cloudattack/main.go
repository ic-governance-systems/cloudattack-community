package main

import (
	"os"

	"cloudattack-community/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
