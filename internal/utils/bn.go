package utils

import (
	"fmt"
	"github.com/fatih/color"
)

func PrintBanner() {
	banner := `
██╗  ██╗ ██████╗ ██████╗  ██████╗ ██╗  ██╗
██║ ██╔╝██╔═══██╗██╔══██╗██╔═══██╗██║ ██╔╝
█████╔╝ ██║   ██║██║  ██║██║   ██║█████╔╝
██╔═██╗ ██║   ██║██║  ██║██║   ██║██╔═██╗
██║  ██╗╚██████╔╝██████╔╝╚██████╔╝██║  ██╗
╚═╝  ╚═╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝
`

	// Color definitions
	darkPink := color.New(color.FgHiMagenta, color.Bold).SprintFunc()
	blueItalic := color.New(color.FgBlue, color.Italic).SprintFunc()
	red := color.New(color.FgRed, color.Bold).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()

	// Print the banner with color
	fmt.Print(darkPink(banner))

	// Additional info
	fmt.Printf(" %s %s | %s %s\n",
		cyan("Version:"), red("v0.0.7"),
		cyan("GitHub:"), blueItalic("github.com/rhyru9/kodok"))

	fmt.Printf(" %s %s\n",
		green("Description:"), "Advanced JavaScript Security & Path Discovery Scanner")

	fmt.Printf(" %s %s\n\n",
		green("Features:"), "Custom Headers • Authentication • Domain Filtering • Batch Scanning")
}