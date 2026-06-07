package cli

import "strings"

// getFlagValue returns the value for a flag like --input file or --flag=value
func getFlagValue(args []string, name string) string {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(a, name+"=") {
			return strings.SplitN(a, "=", 2)[1]
		}
	}
	return ""
}
