package cli

import (
	"fmt"
	"os"

	"cloudattack-community/internal/detector"
	"cloudattack-community/internal/formatter"
)

func runScan(args []string) {
	inputFile := getFlagValue(args, "--input")
	if inputFile == "" {
		fmt.Println("Usage:")
		fmt.Println("  cloudattack scan --input <file>")
		fmt.Println("")
		fmt.Println("Example:")
		fmt.Println("  cloudattack scan --input examples/iam.json")
		return
	}

	data, err := os.ReadFile(inputFile)
	if err != nil {
		fmt.Println("Failed to read file:", err)
		return
	}

	roles := detector.ParseIAM(data)
	findings := detector.RunAnalysis(roles)

	report := formatter.FromFindings(findings)
	fmt.Println(formatter.ToText(report))
}
