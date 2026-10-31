package redact

import "strings"

// defaultEntityMap maps supported entity names to redaction labels. Only person
// labels are enabled by default; other categories require an explicit opt-in.
var defaultEntityMap = map[string]string{
	"PER": "full_name", "PERSON": "full_name", "NAME": "full_name",
	"GIVENNAME": "full_name", "SURNAME": "full_name", "FIRSTNAME": "full_name", "LASTNAME": "full_name",
	"DATE": "date", "DOB": "date", "DATEOFBIRTH": "date",
	"LOC": "location", "GPE": "location", "CITY": "location", "STREET": "address", "ADDRESS": "address",
	"ORG": "org",
}

func entityOf(label string) string {
	return strings.ToUpper(strings.TrimPrefix(strings.TrimPrefix(label, "B-"), "I-"))
}

// Person aliases are enabled by default. Entity selection never activates NER.
func nerEntityLabels(labels, requested []string) map[string]string {
	keep := map[string]string{}
	if len(requested) == 0 {
		for _, label := range labels {
			entity := entityOf(label)
			if mapped, ok := defaultEntityMap[entity]; ok && mapped == "full_name" {
				keep[entity] = mapped
			}
		}
		return keep
	}
	for _, entity := range requested {
		entity = strings.ToUpper(entity)
		if mapped, ok := defaultEntityMap[entity]; ok {
			keep[entity] = mapped
		} else {
			keep[entity] = strings.ToLower(entity)
		}
	}
	return keep
}
