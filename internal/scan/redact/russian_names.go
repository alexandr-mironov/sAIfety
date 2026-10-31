package redact

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// A small hand-maintained vocabulary, not an exhaustive allowlist of people.
var givenNames = nameSet(`Александр Александра Алексей Алина Алла Алёна Алена Анатолий Андрей Анна Антон Антонина Аркадий Арсений Артем Артём Артур Борис Вадим Валентин Валентина Валерий Валерия Василий Вера Виктор Виктория Виталий Владимир Владислав Вячеслав Галина Геннадий Георгий Глеб Григорий Даниил Данила Дарья Денис Дмитрий Евгений Евгения Екатерина Елена Елизавета Зинаида Зоя Иван Игорь Илья Инна Ирина Кирилл Клавдия Константин Ксения Лариса Лев Леонид Лидия Любовь Людмила Максим Маргарита Марина Мария Матвей Михаил Надежда Наталья Наталия Нина Николай Оксана Олег Ольга Павел Петр Пётр Полина Раиса Роман Руслан Светлана Семен Семён Сергей Станислав Степан София Софья Таисия Тамара Татьяна Тимофей Тимур Ульяна Федор Фёдор Юлия Юрий Яков Яна Ярослав`)

func nameSet(s string) map[string]bool {
	m := map[string]bool{}
	for _, n := range strings.Fields(strings.ToLower(s)) {
		m[n] = true
		switch {
		case strings.HasSuffix(n, "ия"):
			root := strings.TrimSuffix(n, "ия")
			for _, e := range []string{"ии", "ию", "ией"} {
				m[root+e] = true
			}
		case strings.HasSuffix(n, "а"):
			root := strings.TrimSuffix(n, "а")
			for _, e := range []string{"ы", "и", "е", "у", "ой"} {
				m[root+e] = true
			}
		case strings.HasSuffix(n, "я"):
			root := strings.TrimSuffix(n, "я")
			for _, e := range []string{"и", "е", "ю", "ей"} {
				m[root+e] = true
			}
		case strings.HasSuffix(n, "ий"), strings.HasSuffix(n, "ей"):
			root := strings.TrimSuffix(n, "й")
			for _, e := range []string{"я", "ю", "ем", "е"} {
				m[root+e] = true
			}
		case strings.HasSuffix(n, "ь"):
			root := strings.TrimSuffix(n, "ь")
			for _, e := range []string{"я", "ю", "ем", "е"} {
				m[root+e] = true
			}
		default:
			for _, e := range []string{"а", "у", "ом", "е"} {
				m[n+e] = true
			}
		}
	}
	return m
}

var ruWord = regexp.MustCompile(`[А-ЯЁа-яё]\.|[А-ЯЁа-яё]+(?:[-‑][А-ЯЁа-яё]+)*`)
var surnameEnding = regexp.MustCompile(`(?i)(?:ов|ев|ёв|ин|ын|ский|цкий|ская|цкая|ко|енко|ук|юк|ич|ых|их|ой|ая|ова|ева|ёва|ина|ына|ову|еву|ину|ого|ому|овой|евой|иной|ским|цким|скому|цкому|скую|цкую|ских|цких|овым|евым|иным|ове|еве|ине)$`)
var patronymicEnding = regexp.MustCompile(`(?i)(?:ович|евич|ёвич|ьич|ич|овна|евна|ёвна|инична|ична|овича|евича|ьича|овичу|евичу|ьичу|овичем|евичем|ьичем|овиче|евиче|овны|евны|ичны|овне|евне|ичне|овну|евну|ичну|овной|евной|ичной)$`)
var explicitNameContext = regexp.MustCompile(`(?i)(?:фио|контактное лицо|ответственн[а-яё]*(?:[ \t]+[а-яё]+){0,3}|получател[а-яё]*|отправител[а-яё]*)[ \t]*[:=][ \t]*$`)

var nameContext = regexp.MustCompile(`(?i)(?:фио|имя|фамилия|отчество|контакт(?:ное лицо)?|клиент|сотрудник|ответственн[а-яё]*|подписал[а-яё]*|проверил[а-яё]*|согласовал[а-яё]*|получател[а-яё]*|отправител[а-яё]*)(?:\([а-яё]+\))?[ \t:—–=-]*$`)

type nameWord struct {
	start, end int
	value      string
}

func russianNames(text string) []Match {
	indexes := ruWord.FindAllStringIndex(text, -1)
	words := make([]nameWord, 0, len(indexes))
	for _, m := range indexes {
		words = append(words, nameWord{m[0], m[1], text[m[0]:m[1]]})
	}
	var out []Match
	for i := 0; i < len(words); i++ {
		for size := 3; size >= 2; size-- {
			if i+size > len(words) {
				continue
			}
			chunk := words[i : i+size]
			if !nameBoundary(text, chunk[0].start, chunk[len(chunk)-1].end) {
				continue
			}
			connected := true
			for j := 1; j < len(chunk); j++ {
				gap := text[chunk[j-1].end:chunk[j].start]
				if strings.Trim(gap, " \t\u00a0\u202f") != "" || len(gap) > 16 {
					connected = false
				}
			}
			if !connected {
				continue
			}
			before := text[max(0, chunk[0].start-100):chunk[0].start]
			if nameSequence(chunk, nameContext.MatchString(before), explicitNameContext.MatchString(before)) {
				out = append(out, Match{Kind: KindPII, Label: "full_name", Start: chunk[0].start, End: chunk[len(chunk)-1].end, Confidence: 0.85})
				i += size - 1
				break
			}
		}
	}
	return out
}

func nameSequence(ws []nameWord, context, explicit bool) bool {
	given := func(i int) bool { return isGiven(ws[i].value) }
	family := func(i int) bool {
		return nameToken(ws[i].value) && !isGiven(ws[i].value) && (surnameEnding.MatchString(ws[i].value) || context && unicode.IsUpper([]rune(ws[i].value)[0]))
	}
	patron := func(i int) bool { return patronymicEnding.MatchString(ws[i].value) }
	initial := func(i int) bool { v := []rune(ws[i].value); return len(v) == 2 && v[1] == '.' }
	capital := func(i int) bool { r, _ := utf8.DecodeRuneInString(ws[i].value); return unicode.IsUpper(r) }
	if len(ws) == 3 {
		knownOrContext := func(i int) bool { return given(i) || nameToken(ws[i].value) && (explicit || capital(i)) }
		return knownOrContext(0) && patron(1) && (family(2) || (capital(2) || explicit) && nameToken(ws[2].value)) ||
			(family(0) || (capital(0) || explicit) && nameToken(ws[0].value)) && knownOrContext(1) && patron(2) ||
			family(0) && initial(1) && initial(2) || initial(0) && initial(1) && family(2)
	}
	if !context && (!capital(0) || !capital(1)) {
		return false
	}
	return given(0) && (family(1) || patron(1)) || family(0) && given(1)
}

func isGiven(s string) bool {
	for _, part := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return r == '-' || r == '‑' }) {
		if !givenNames[part] {
			return false
		}
	}
	return s != ""
}

func nameToken(s string) bool {
	if utf8.RuneCountInString(s) < 2 {
		return false
	}
	for _, r := range s {
		if r >= 'А' && r <= 'я' || r == 'Ё' || r == 'ё' || r == '-' || r == '‑' {
			continue
		}
		return false
	}
	return !nonNameValues[strings.ToLower(s)]
}

var nonNameValues = map[string]bool{"подписал": true, "подписала": true, "согласовал": true, "согласовала": true, "проверил": true, "проверила": true, "получил": true, "получила": true, "ответственный": true, "связаться": true, "протокол": true, "контакт": true, "строка": true, "число": true, "объект": true, "массив": true, "нет": true, "не": true, "неизвестно": true, "пусто": true, "фамилия": true, "имя": true, "отчество": true, "клиент": true, "сотрудник": true, "тип": true, "тест": true, "данные": true}

func nameBoundary(text string, start, end int) bool {
	if start > 0 {
		r, _ := utf8.DecodeLastRuneInString(text[:start])
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			return false
		}
	}
	if end < len(text) {
		r, _ := utf8.DecodeRuneInString(text[end:])
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			return false
		}
	}
	return true
}
