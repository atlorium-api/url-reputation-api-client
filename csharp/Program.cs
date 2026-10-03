// Клиент API проверки ссылки Atlorium — репутация URL: фишинг, вредонос,
// нежелательное ПО.
//
// Запуск (работает сразу, без регистрации — на демо-ключе):
//     dotnet run
//
// Боевой ключ: получить на https://atlorium.com и положить в переменную окружения
// ATLORIUM_API_KEY. Код при этом не меняется.

using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

// Публичный демо-ключ. С ним API отвечает правдоподобными МОКАМИ (не реальными
// данными репутационной базы) — чтобы можно было встроить и протестировать
// интеграцию до оплаты. Ответы детерминированы: один и тот же адрес всегда даёт
// один и тот же вердикт, поэтому на них можно писать стабильные тесты.
const string SandboxKey = "ak_sandbox_demo_mockdata_v1";

var apiKey = Environment.GetEnvironmentVariable("ATLORIUM_API_KEY") ?? SandboxKey;
var baseUrl = Environment.GetEnvironmentVariable("ATLORIUM_BASE_URL") ?? "https://atlorium.com";

using var http = new HttpClient
{
    BaseAddress = new Uri(baseUrl),
    Timeout = TimeSpan.FromSeconds(30),
};
http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

var client = new UrlCheckClient(http);

if (apiKey == SandboxKey)
{
    Console.WriteLine("Демо-ключ: ответы сгенерированы (моки), не реальные данные.\n");
}

// Адреса из зарезервированной под примеры зоны example.com. В песочнице ветку
// ответа задаёт домен, поэтому набор ниже показывает все содержательные исходы.
string[] demoLinks =
[
    "https://example.com/offer",
    "http://phishing.example.com/login",
    "https://unwanted.example.com/download",
    "https://danger.example.com/pay",
];

var links = args.Length > 0 ? args : demoLinks;

UrlThreatResult single;
UrlThreatBatchResponse batch;
try
{
    // Одиночная проверка — показать, как выглядит ответ по одному адресу.
    single = await client.CheckUrlAsync(links[0]);
    // Пакетная проверка — так модерируют весь текст сразу, одним запросом.
    batch = await client.CheckUrlsAsync(links);
}
catch (AtloriumException error)
{
    Console.Error.WriteLine($"Ошибка: {error.Message}");
    return 1;
}

Console.WriteLine($"Одиночная проверка: {single.Url}");
Console.WriteLine($"  Вердикт: {single.Verdict} · проверено {ContentScreening.Stamp(single.CheckedAtUtc)}");
Console.WriteLine($"  {single.Message}\n");

Console.WriteLine($"Пакет: ссылок {batch.Total}, опасных {batch.ThreatCount}, "
                  + $"без вердикта {batch.UnknownCount}\n");

var decision = ContentScreening.Screen(batch.Results);
foreach (var link in decision.Links)
{
    Console.WriteLine($"  {ContentScreening.ActionMark(link.Action)} {link.Url}");
    Console.WriteLine($"       {link.Reason} · проверено {link.CheckedAt}");
}

Console.WriteLine($"\n{ContentScreening.VerdictLine(decision.Decision)}");
foreach (var note in decision.Notes)
{
    Console.WriteLine($"  [i] {note}");
}

// В своём конвейере модерации решение обычно превращают в код возврата
// (reject — ненулевой), чтобы шаг падал сам и публикация не уходила дальше.
// Пример этого не делает намеренно: демо-набор ссылок заведомо содержит
// опасные, и прогон примеров падал бы на каждом запуске.
return 0;

// ── Клиент ───────────────────────────────────────────────────────────────────

/// <summary>Ошибка API: HTTP-код разложен в человекочитаемую причину.</summary>
public sealed class AtloriumException(HttpStatusCode status, string body)
    : Exception($"HTTP {(int)status}: {Explain(status)}. Ответ сервера: {body[..Math.Min(200, body.Length)]}")
{
    public HttpStatusCode Status { get; } = status;

    private static string Explain(HttpStatusCode status) => (int)status switch
    {
        400 => "Ссылка не указана или не распознана (нужен адрес http/https)",
        401 => "API-ключ отсутствует, просрочен или недействителен",
        402 => "Недостаточно кредитов на балансе — пополните на https://atlorium.com",
        429 => "Превышен лимит запросов — повторите позже",
        503 => "Проверить ссылку не удалось (за сбой на своей стороне мы не списываем деньги)",
        _ => "Неизвестная ошибка",
    };
}

public sealed class UrlCheckClient(HttpClient http)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    /// <summary>
    /// Потолок ожидания при 429. Исчерпав часовое окно, сервер честно просит подождать
    /// десятки минут — и клиент, слепо доверяющий заголовку Retry-After, «зависнет» на
    /// всё это время. Дольше потолка не ждём, а честно сообщаем, что лимит исчерпан.
    /// </summary>
    private const int MaxRetryDelaySeconds = 120;

    /// <summary>
    /// GET /api/urlcheck — вердикт по одной ссылке.
    /// </summary>
    /// <remarks>
    /// Схему можно опустить: «example.com/page» будет приведено к «http://example.com/page».
    /// В ответе адрес возвращается в приведённом виде — именно в нём он и проверялся.
    /// </remarks>
    public async Task<UrlThreatResult> CheckUrlAsync(string url)
    {
        var json = await SendAsync(() => new HttpRequestMessage(
            HttpMethod.Get, $"/api/urlcheck?url={Uri.EscapeDataString(url)}"));

        return JsonSerializer.Deserialize<UrlThreatResult>(json, JsonOptions)
               ?? throw new InvalidOperationException("Пустой ответ API.");
    }

    /// <summary>
    /// POST /api/urlcheck/batch — до 100 ссылок за один вызов.
    /// </summary>
    /// <remarks>
    /// Порядок результатов совпадает с порядком присланных ссылок. Пустые строки и
    /// повторы сервер отбрасывает до проверки: повтор не добавляет работы.
    /// </remarks>
    public async Task<UrlThreatBatchResponse> CheckUrlsAsync(IReadOnlyList<string> urls)
    {
        var json = await SendAsync(() => new HttpRequestMessage(HttpMethod.Post, "/api/urlcheck/batch")
        {
            Content = JsonContent.Create(urls),
        });

        return JsonSerializer.Deserialize<UrlThreatBatchResponse>(json, JsonOptions)
               ?? throw new InvalidOperationException("Пустой ответ API.");
    }

    /// <summary>
    /// Отправляет запрос и один раз повторяет его на 429, если сервер просит
    /// подождать разумное время. Фабрика нужна потому, что HttpRequestMessage
    /// нельзя отправить дважды.
    /// </summary>
    private async Task<string> SendAsync(Func<HttpRequestMessage> factory)
    {
        for (var attempt = 1; attempt <= 2; attempt++)
        {
            using var request = factory();
            using var response = await http.SendAsync(request);
            var body = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                return body;
            }

            var delay = response.StatusCode == HttpStatusCode.TooManyRequests
                ? RetryAfterSeconds(response)
                : 0;

            if (attempt == 1 && delay > 0)
            {
                await Task.Delay(TimeSpan.FromSeconds(delay));
                continue;
            }

            throw new AtloriumException(response.StatusCode, body);
        }

        throw new InvalidOperationException("недостижимо");
    }

    /// <summary>Пауза из заголовка Retry-After, но не дольше потолка. 0 — не ждать.</summary>
    private static int RetryAfterSeconds(HttpResponseMessage response)
    {
        var seconds = response.Headers.RetryAfter?.Delta?.TotalSeconds;
        if (seconds is not > 0)
        {
            return 0;
        }
        return seconds <= MaxRetryDelaySeconds ? (int)seconds.Value : 0;
    }
}

// ── Модель ответа ────────────────────────────────────────────────────────────

/// <summary>Вердикт по одной ссылке.</summary>
public sealed record UrlThreatResult
{
    /// <summary>Адрес в приведённом виде — именно в нём он и проверялся.</summary>
    public string Url { get; init; } = "";

    /// <summary>clean — отметок нет, threat — угроза, unknown — вердикт не получен.</summary>
    public string Verdict { get; init; } = "";

    /// <summary>Список категорий: один адрес может быть отмечен сразу по нескольким.</summary>
    public IReadOnlyList<string> ThreatTypes { get; init; } = [];

    /// <summary>
    /// Момент проверки. Показывайте его рядом с вердиктом: он датирует утверждение.
    /// </summary>
    public DateTimeOffset CheckedAtUtc { get; init; }

    public string Message { get; init; } = "";

    public long ElapsedMs { get; init; }
}

/// <summary>Ответ пакетной проверки.</summary>
public sealed record UrlThreatBatchResponse
{
    /// <summary>Вердикты в том же порядке, в каком были присланы ссылки.</summary>
    public IReadOnlyList<UrlThreatResult> Results { get; init; } = [];

    public int Total { get; init; }

    public int ThreatCount { get; init; }

    /// <summary>Сколько строк осталось без вердикта. Они не тарифицируются.</summary>
    public int UnknownCount { get; init; }

    public long ElapsedMs { get; init; }
}

// ── Применение данных: модерация ссылок в пользовательском контенте ───────────
// Вердикт сам по себе — просто строка. Ценность появляется, когда по нему
// принимают решение о публикации. Ниже — правила, по которым объявление,
// комментарий или сообщение в чате пропускают, отправляют модератору или
// отклоняют.
//
// Правила намеренно разные для разных категорий угрозы:
//   * фишинг и вредонос — прямой ущерб посетителю, публиковать нельзя;
//   * нежелательное ПО — граница размытая, решает человек;
//   * вердикта нет — «не проверено» не равно «безопасно», тоже к человеку.

public enum LinkAction { Allow, Review, Reject }

public enum ContentAction { Publish, Hold, Reject }

public sealed record LinkDecision(string Url, LinkAction Action, string Reason, string CheckedAt);

public sealed record ContentDecision(
    ContentAction Decision,
    IReadOnlyList<LinkDecision> Links,
    IReadOnlyList<string> Notes);

public static class ContentScreening
{
    /// <summary>Категории угрозы, при которых публиковать нельзя ни при каких условиях.</summary>
    private static readonly string[] BlockingThreats = ["social_engineering", "malware"];

    /// <summary>
    /// Порог «протухания» вердикта. Репутационная база пополняется постоянно, поэтому
    /// ответ — это утверждение НА МОМЕНТ ПРОВЕРКИ.
    /// </summary>
    private static readonly TimeSpan StaleVerdictAge = TimeSpan.FromHours(24);

    public static ContentDecision Screen(IReadOnlyList<UrlThreatResult> results)
    {
        var links = new List<LinkDecision>(results.Count);
        var notes = new List<string>();
        var staleClean = 0;

        foreach (var result in results)
        {
            LinkAction action;
            string reason;

            if (result.Verdict == "threat")
            {
                // ThreatTypes — СПИСОК: один адрес может быть отмечен сразу по
                // нескольким категориям. Разбор по первому элементу теряет остальные.
                var names = string.Join(", ", result.ThreatTypes.Select(Name));
                var blocking = result.ThreatTypes.Any(BlockingThreats.Contains);
                action = blocking ? LinkAction.Reject : LinkAction.Review;
                reason = (blocking ? "опасная ссылка: " : "спорная ссылка: ") + names;
            }
            else if (result.Verdict == "unknown")
            {
                // Вердикта нет — и это не то же самое, что «чисто». Такую строку сервис
                // не тарифицирует, а публиковать её вслепую не стоит.
                action = LinkAction.Review;
                reason = "вердикт получить не удалось";
            }
            else
            {
                action = LinkAction.Allow;
                reason = "отметок об угрозе нет";
                // Возраст важен именно у «чисто»: это единственный вердикт, на
                // основании которого мы что-то пропускаем.
                if (DateTimeOffset.UtcNow - result.CheckedAtUtc > StaleVerdictAge)
                {
                    staleClean++;
                }
            }

            links.Add(new LinkDecision(result.Url, action, reason, Stamp(result.CheckedAtUtc)));
        }

        var decision = ContentAction.Publish;
        if (links.Any(link => link.Action == LinkAction.Reject))
        {
            decision = ContentAction.Reject;
        }
        else if (links.Any(link => link.Action == LinkAction.Review))
        {
            decision = ContentAction.Hold;
        }

        if (staleClean > 0)
        {
            notes.Add($"Вердикт «чисто» по {staleClean} ссылке(-ам) старше суток. «Чисто» — это "
                      + "состояние базы на момент проверки, а не гарантия: перед долгой публикацией перепроверьте.");
        }

        return new ContentDecision(decision, links, notes);
    }

    /// <summary>Отметка времени в том же виде, в каком её отдаёт API.</summary>
    public static string Stamp(DateTimeOffset moment) =>
        moment.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture);

    public static string ActionMark(LinkAction action) => action switch
    {
        LinkAction.Allow => "[ok]",
        LinkAction.Review => "[?]",
        _ => "[!]",
    };

    public static string VerdictLine(ContentAction decision) => decision switch
    {
        ContentAction.Publish => "ПУБЛИКОВАТЬ: опасных ссылок нет.",
        ContentAction.Hold => "НА МОДЕРАЦИЮ: есть ссылки, по которым нужен человек.",
        _ => "ОТКЛОНИТЬ: в тексте есть опасные ссылки.",
    };

    private static string Name(string threat) => threat switch
    {
        "social_engineering" => "фишинг",
        "malware" => "вредоносное ПО",
        "unwanted_software" => "нежелательное ПО",
        _ => threat,
    };
}
