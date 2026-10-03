// Клиент API проверки ссылки Atlorium — репутация URL: фишинг, вредонос,
// нежелательное ПО.
//
// Запуск (работает сразу, без регистрации — на демо-ключе):
//
//	go run .
//
// Боевой ключ: получить на https://atlorium.com и положить в переменную окружения
// ATLORIUM_API_KEY. Код при этом не меняется.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// SandboxKey — публичный демо-ключ. С ним API отвечает правдоподобными МОКАМИ
// (не реальными данными репутационной базы), чтобы можно было встроить
// интеграцию до оплаты. Ответы детерминированы — на них можно писать стабильные тесты.
const SandboxKey = "ak_sandbox_demo_mockdata_v1"

const (
	// MaxRetryDelay — потолок ожидания при 429. Исчерпав часовое окно, сервер
	// честно просит подождать десятки минут — и клиент, слепо доверяющий
	// заголовку Retry-After, «зависнет» на всё это время.
	MaxRetryDelay = 120 * time.Second

	// StaleVerdictAge — порог «протухания» вердикта. Репутационная база
	// пополняется постоянно, поэтому ответ — это утверждение НА МОМЕНТ ПРОВЕРКИ.
	StaleVerdictAge = 24 * time.Hour
)

var (
	apiKey  = envOr("ATLORIUM_API_KEY", SandboxKey)
	baseURL = envOr("ATLORIUM_BASE_URL", "https://atlorium.com")
	client  = &http.Client{Timeout: 30 * time.Second}
)

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

// UrlThreatResult — вердикт по одной ссылке.
type UrlThreatResult struct {
	// URL — адрес в приведённом виде: именно в нём он и проверялся.
	URL     string `json:"url"`
	Verdict string `json:"verdict"` // clean | threat | unknown
	// ThreatTypes — список категорий: один адрес может быть отмечен сразу по нескольким.
	ThreatTypes []string `json:"threatTypes"`
	// CheckedAtUtc — момент проверки. Показывайте его рядом с вердиктом:
	// он датирует утверждение.
	CheckedAtUtc string `json:"checkedAtUtc"`
	Message      string `json:"message"`
	ElapsedMs    int64  `json:"elapsedMs"`
}

// UrlThreatBatchResponse — ответ пакетной проверки.
type UrlThreatBatchResponse struct {
	// Results — вердикты в том же порядке, в каком были присланы ссылки.
	Results     []UrlThreatResult `json:"results"`
	Total       int               `json:"total"`
	ThreatCount int               `json:"threatCount"`
	// UnknownCount — сколько строк осталось без вердикта. Они не тарифицируются.
	UnknownCount int   `json:"unknownCount"`
	ElapsedMs    int64 `json:"elapsedMs"`
}

// APIError раскладывает HTTP-код в человекочитаемую причину.
type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string {
	reasons := map[int]string{
		400: "ссылка не указана или не распознана (нужен адрес http/https)",
		401: "API-ключ отсутствует, просрочен или недействителен",
		402: "недостаточно кредитов на балансе — пополните на https://atlorium.com",
		429: "превышен лимит запросов — повторите позже",
		503: "проверить ссылку не удалось (за сбой на своей стороне мы не списываем деньги)",
	}
	reason, ok := reasons[e.Status]
	if !ok {
		reason = "неизвестная ошибка"
	}
	return fmt.Sprintf("HTTP %d: %s. Ответ сервера: %s", e.Status, reason, e.Body)
}

// retryAfter возвращает паузу из заголовка Retry-After, но не дольше потолка.
func retryAfter(response *http.Response) time.Duration {
	seconds, err := strconv.Atoi(response.Header.Get("Retry-After"))
	if err != nil || seconds <= 0 {
		return 0
	}
	if delay := time.Duration(seconds) * time.Second; delay <= MaxRetryDelay {
		return delay
	}
	return 0
}

func do(method, path string, query url.Values, payload []byte) ([]byte, error) {
	endpoint := baseURL + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}

	for attempt := 1; attempt <= 2; attempt++ {
		var body io.Reader
		if payload != nil {
			body = bytes.NewReader(payload)
		}

		request, err := http.NewRequest(method, endpoint, body)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Authorization", "Bearer "+apiKey)
		request.Header.Set("Accept", "application/json")
		if payload != nil {
			request.Header.Set("Content-Type", "application/json")
		}

		response, err := client.Do(request)
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			return nil, err
		}

		if response.StatusCode == http.StatusOK {
			return data, nil
		}

		// Один повтор на 429 — и только если сервер просит подождать разумное время.
		if attempt == 1 && response.StatusCode == http.StatusTooManyRequests {
			if delay := retryAfter(response); delay > 0 {
				time.Sleep(delay)
				continue
			}
		}
		return nil, &APIError{Status: response.StatusCode, Body: string(data)}
	}

	return nil, fmt.Errorf("недостижимо")
}

// CheckURL вызывает GET /api/urlcheck — вердикт по одной ссылке.
//
// Схему можно опустить: «example.com/page» будет приведено к «http://example.com/page».
// В ответе адрес возвращается в приведённом виде — именно в нём он и проверялся.
func CheckURL(link string) (*UrlThreatResult, error) {
	data, err := do(http.MethodGet, "/api/urlcheck", url.Values{"url": {link}}, nil)
	if err != nil {
		return nil, err
	}
	var result UrlThreatResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// CheckURLs вызывает POST /api/urlcheck/batch — до 100 ссылок за один вызов.
//
// Порядок результатов совпадает с порядком присланных ссылок. Пустые строки и
// повторы сервер отбрасывает до проверки: повтор не добавляет работы.
func CheckURLs(links []string) (*UrlThreatBatchResponse, error) {
	payload, err := json.Marshal(links)
	if err != nil {
		return nil, err
	}
	data, err := do(http.MethodPost, "/api/urlcheck/batch", nil, payload)
	if err != nil {
		return nil, err
	}
	var batch UrlThreatBatchResponse
	if err := json.Unmarshal(data, &batch); err != nil {
		return nil, err
	}
	return &batch, nil
}

// ── Применение данных: модерация ссылок в пользовательском контенте ───────────
// Вердикт сам по себе — просто строка. Ценность появляется, когда по нему
// принимают решение о публикации. Ниже — правила, по которым объявление,
// комментарий или сообщение в чате пропускают, отправляют модератору или
// отклоняют.
//
// Правила намеренно разные для разных категорий угрозы:
//   - фишинг и вредонос — прямой ущерб посетителю, публиковать нельзя;
//   - нежелательное ПО — граница размытая, решает человек;
//   - вердикта нет — «не проверено» не равно «безопасно», тоже к человеку.

// LinkDecision — что делать с одной ссылкой.
type LinkDecision struct {
	URL       string
	Action    string // allow | review | reject
	Reason    string
	CheckedAt string
}

// ContentDecision — что делать со всей публикацией.
type ContentDecision struct {
	Decision string // publish | hold | reject
	Links    []LinkDecision
	Notes    []string
}

// blockingThreats — категории, при которых публиковать нельзя ни при каких условиях.
var blockingThreats = map[string]bool{
	"social_engineering": true,
	"malware":            true,
}

var threatNames = map[string]string{
	"social_engineering": "фишинг",
	"malware":            "вредоносное ПО",
	"unwanted_software":  "нежелательное ПО",
}

// isStale сообщает, старше ли вердикт порога. Некорректную отметку считаем несвежей.
func isStale(checkedAt string) bool {
	moment, err := time.Parse(time.RFC3339, checkedAt)
	if err != nil {
		return true
	}
	return time.Since(moment) > StaleVerdictAge
}

// ScreenUserContent решает судьбу публикации по вердиктам всех ссылок в ней.
func ScreenUserContent(results []UrlThreatResult) ContentDecision {
	decision := ContentDecision{Decision: "publish"}
	staleClean := 0

	for _, result := range results {
		checkedAt := result.CheckedAtUtc
		if checkedAt == "" {
			checkedAt = "—"
		}

		var action, reason string
		switch result.Verdict {
		case "threat":
			// ThreatTypes — СПИСОК: один адрес может быть отмечен сразу по
			// нескольким категориям. Разбор по первому элементу теряет остальные.
			names := make([]string, 0, len(result.ThreatTypes))
			blocking := false
			for _, threat := range result.ThreatTypes {
				if name, ok := threatNames[threat]; ok {
					names = append(names, name)
				} else {
					names = append(names, threat)
				}
				if blockingThreats[threat] {
					blocking = true
				}
			}
			if blocking {
				action, reason = "reject", "опасная ссылка: "+strings.Join(names, ", ")
			} else {
				action, reason = "review", "спорная ссылка: "+strings.Join(names, ", ")
			}
		case "unknown":
			// Вердикта нет — и это не то же самое, что «чисто». Такую строку сервис
			// не тарифицирует, а публиковать её вслепую не стоит.
			action, reason = "review", "вердикт получить не удалось"
		default:
			action, reason = "allow", "отметок об угрозе нет"
			// Возраст важен именно у «чисто»: это единственный вердикт, на
			// основании которого мы что-то пропускаем.
			if isStale(result.CheckedAtUtc) {
				staleClean++
			}
		}

		decision.Links = append(decision.Links, LinkDecision{
			URL: result.URL, Action: action, Reason: reason, CheckedAt: checkedAt,
		})
	}

	for _, link := range decision.Links {
		if link.Action == "reject" {
			decision.Decision = "reject"
			break
		}
		if link.Action == "review" {
			decision.Decision = "hold"
		}
	}

	if staleClean > 0 {
		decision.Notes = append(decision.Notes, fmt.Sprintf(
			"Вердикт «чисто» по %d ссылке(-ам) старше суток. «Чисто» — это состояние базы "+
				"на момент проверки, а не гарантия: перед долгой публикацией перепроверьте.", staleClean))
	}

	return decision
}

// ── Демонстрация ─────────────────────────────────────────────────────────────

// demoLinks — адреса из зарезервированной под примеры зоны example.com.
// В песочнице ветку ответа задаёт домен, поэтому набор показывает все
// содержательные исходы.
var demoLinks = []string{
	"https://example.com/offer",
	"http://phishing.example.com/login",
	"https://unwanted.example.com/download",
	"https://danger.example.com/pay",
}

var actionMarks = map[string]string{"allow": "[ok]", "review": "[?]", "reject": "[!]"}

var verdictLine = map[string]string{
	"publish": "ПУБЛИКОВАТЬ: опасных ссылок нет.",
	"hold":    "НА МОДЕРАЦИЮ: есть ссылки, по которым нужен человек.",
	"reject":  "ОТКЛОНИТЬ: в тексте есть опасные ссылки.",
}

func main() {
	if apiKey == SandboxKey {
		fmt.Println("Демо-ключ: ответы сгенерированы (моки), не реальные данные.")
		fmt.Println()
	}

	links := demoLinks
	if len(os.Args) > 1 {
		links = os.Args[1:]
	}

	// Одиночная проверка — показать, как выглядит ответ по одному адресу.
	single, err := CheckURL(links[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "Ошибка:", err)
		os.Exit(1)
	}
	fmt.Printf("Одиночная проверка: %s\n", single.URL)
	fmt.Printf("  Вердикт: %s · проверено %s\n", single.Verdict, single.CheckedAtUtc)
	fmt.Printf("  %s\n\n", single.Message)

	// Пакетная проверка — так модерируют весь текст сразу, одним запросом.
	batch, err := CheckURLs(links)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Ошибка:", err)
		os.Exit(1)
	}
	fmt.Printf("Пакет: ссылок %d, опасных %d, без вердикта %d\n\n",
		batch.Total, batch.ThreatCount, batch.UnknownCount)

	decision := ScreenUserContent(batch.Results)
	for _, link := range decision.Links {
		fmt.Printf("  %s %s\n", actionMarks[link.Action], link.URL)
		fmt.Printf("       %s · проверено %s\n", link.Reason, link.CheckedAt)
	}

	fmt.Printf("\n%s\n", verdictLine[decision.Decision])
	for _, note := range decision.Notes {
		fmt.Println("  [i]", note)
	}

	// В своём конвейере модерации решение обычно превращают в код возврата
	// (reject — ненулевой), чтобы шаг падал сам и публикация не уходила дальше.
	// Пример этого не делает намеренно: демо-набор ссылок заведомо содержит
	// опасные, и прогон примеров падал бы на каждом запуске.
}
