package cli

import (
	"fmt"
	"os"
)

func Execute() {
	if len(os.Args) < 2 {
		printHelp()
		return
	}

	switch os.Args[1] {
	case "scan":
		runScan(os.Args[2:])
	case "version":
		runVersion()
	default:
		fmt.Println("Unknown command:", os.Args[1])
		printHelp()
	}
}

func printHelp() {
	fmt.Println("=== CloudAttack Community Edition ===")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  cloudattack scan --input <file>")
	fmt.Println("  cloudattack version")
	fmt.Println()
}
