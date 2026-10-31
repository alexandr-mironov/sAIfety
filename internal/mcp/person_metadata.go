package mcp

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/saifety-org/sAIfety/internal/scan/normalize"
	"github.com/saifety-org/sAIfety/internal/scan/redact"
	"golang.org/x/text/language"
)

// Metadata is an exception to the parent person-data contract only when both
// its key and value fit a supported descriptor. A key alone is not evidence:
// {"full_name":{"label":"John Smith"}} still contains personal data.
// This deliberately favors privacy over preserving arbitrary UI copy.
func personMetadataValue(key string, value any) bool {
	key = strings.TrimPrefix(key, "x-")
	switch key {
	case "enabled", "visible", "hidden", "disabled", "editable":
		_, ok := value.(bool)
		return ok
	}
	text, ok := value.(string)
	if !ok {
		return false
	}
	switch key {
	case "language", "lang", "locale":
		if text == "C" || text == "POSIX" {
			return true
		}
		if !personLocaleCode.MatchString(text) {
			return false
		}
		_, err := language.Parse(strings.ReplaceAll(text, "_", "-"))
		return err == nil
	case "widget":
		switch text {
		case "text", "input", "textbox", "textarea", "hidden", "select", "combobox", "autocomplete", "name", "person-name":
			return true
		}
	case "encoding":
		switch strings.ToLower(text) {
		case "utf-8", "utf8", "utf-16", "utf16", "utf-16le", "utf-16be", "ascii", "base64", "hex", "unicode", "plain":
			return true
		}
	case "label", "title", "description":
		if redact.PersonField(text) {
			return true
		}
		switch strings.ToLower(text) {
		case "", "name", "display name", "legal name", "preferred name", "user field", "field definition":
			return true
		}
		return personUIDescriptor(text)
	}
	return false
}

// A bounded technical spelling, not arbitrary prose or a full BCP-47 parser.
// Private-use/extensions are excluded so they cannot carry an uninspected name.
var personLocaleCode = regexp.MustCompile(`^[a-z]{2,3}(?:[-_][A-Z][a-z]{3})?(?:[-_](?:[A-Z]{2}|[0-9]{3}))?$`)

// Recognize composed UI copy, not arbitrary prose containing an UI keyword.
// Every word must be known, including text after a colon or a valid prefix.
// Unknown words keep the person context, regardless of case or writing system.
func personUIDescriptor(text string) bool {
	if len(text) > 1024 {
		return false
	}
	text = strings.ToLower(normalize.Text(text))
	for i, r := range text {
		// Internal full stops may be name initials; a sentence terminator is OK.
		if r == '.' && i != len(text)-1 {
			return false
		}
		if !unicode.IsLetter(r) && !unicode.IsMark(r) && !unicode.IsDigit(r) && !unicode.IsSpace(r) && !strings.ContainsRune(".,:;!?()[]{}'\"/-", r) {
			return false
		}
	}
	words := strings.FieldsFunc(text, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsMark(r) })
	if len(words) < 2 || len(words) > 32 {
		return false
	}
	firstTerm := ""
	differentTerm, head := false, false
	for _, word := range words {
		role, ok := personUIWords[word]
		if !ok {
			return false
		}
		if role != descriptorJoin {
			if firstTerm == "" {
				firstTerm = word
			} else if word != firstTerm {
				differentTerm = true
			}
		}
		head = head || role == descriptorHead
	}
	// An article/initial plus a surname such as "A. Field" is insufficient.
	return head && differentTerm
}

const (
	descriptorJoin uint8 = iota
	descriptorTerm
	descriptorHead
)

// Small, explicit bilingual UI vocabulary. No capitalization heuristic, person
// dictionary, model, downloads, or arbitrary user-provided phrases are involved.
// Unsupported vocabulary falls back to masking; word/name collisions remain an
// inherent ambiguity, just as for the existing type and absence descriptors.
var personUIWords = func() map[string]uint8 {
	words := make(map[string]uint8)
	for _, group := range []struct {
		role  uint8
		words string
	}{
		{descriptorJoin, "the for of to in as on and or для в на или по из и как"},
		{descriptorTerm, `public private optional required additional preferred primary secondary legal full given first last middle family display contact customer recipient profile account user personal shipping billing delivery form identity checkout brief short
			enter provide select choose type fill please your this shown
			полное полный полная личное личный личные отображаемое отображаемая отображаемый дополнительное дополнительная дополнительный дополнительные
			необязательное необязательный обязательное обязательный публичное публичная публичный текстовое текстовый краткое краткая краткий
			пользователя покупателя клиента получателя профиля доставки анкеты заполнения учётной учетной записи
			введите укажите выберите заполните пожалуйста ваше ваш ваша`},
		{descriptorHead, `name names field fields label labels caption captions input inputs details information data settings help hint value values text placeholder definition instructions preview annotation summary control
			имя имени фамилия фамилию отчество фио поле поля полей значение значения текст подпись подписи подсказка подсказки описание данные сведения
			контакт профиль ввод ввода название наименование отображение доставка информация информации аннотация настройки`},
	} {
		for _, word := range strings.Fields(group.words) {
			words[word] = group.role
		}
	}
	return words
}()
