package parser

import (
	"regexp"
)

func Parse(content string) []string {
	regex := regexp.MustCompile(`(?:"|')(https?:\/\/[^"'\/]+[^"']*|(?:\/|\.\.?\/)[^"'><,;| *()(%%$^/\\\[\]][^"'><,;|()]*)(?:"|')`)

	matches := regex.FindAllString(content, -1)

	uniqueMatches := make(map[string]bool)
	for _, match := range matches {
		cleanedMatch := match[1 : len(match)-1]
		uniqueMatches[cleanedMatch] = true
	}

	var results []string
	for match := range uniqueMatches {
		results = append(results, match)
	}

	return results
}
