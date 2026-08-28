package cli

import (
	"fmt"
	"os"
)

func Execute() int {
	if len(os.Args) < 2 {
		printHelp()
		return 2
	}

	switch os.Args[1] {
	case "scan":
		return runScan(os.Args[2:])
	case "version":
		runVersion()
		return 0
	default:
		fmt.Fprintln(os.Stderr, "Unknown command:", os.Args[1])
		printHelp()
		return 2
	}
}

func printHelp() {
	fmt.Println("=== CloudAttack Community Edition ===")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  cloudattack scan --input <file>")
	fmt.Println("  cloudattack scan --terraform-plan <file>")
	fmt.Println("  cloudattack scan --input <file> [--format text|json|sarif] [--fail-on <severity>]")
	fmt.Println("  cloudattack version")
	fmt.Println()
}
