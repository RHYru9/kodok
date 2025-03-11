package utils

import (
	"fmt"

	"github.com/fatih/color"
)

func PrintBanner() {
	banner := `
    __ __          __      __  
   / //_/___  ____/ /___  / /__
  / ,< / __ \/ __  / __ \/ //_/
 / /| / /_/ / /_/ / /_/ / ,<   
/_/ |_\____/\__,_/\____/_/|_|  
`

	darkPink := color.New(color.FgHiMagenta).SprintFunc()
	blueItalic := color.New(color.FgBlue, color.Italic).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()

	fmt.Println(darkPink(banner))
	fmt.Printf("               Version [%s] [%s]\n\n", red("0.0.1"), blueItalic("github.com/rhyru9/kodok"))
}
