<?php

/**
 * Клиент API проверки ссылки Atlorium — репутация URL: фишинг, вредонос,
 * нежелательное ПО.
 *
 * Запуск (работает сразу, без регистрации — на демо-ключе):
 *   php main.php
 *
 * Боевой ключ: получить на https://atlorium.com и положить в переменную окружения
 * ATLORIUM_API_KEY. Код при этом не меняется.
 */

declare(strict_types=1);

/**
 * Публичный демо-ключ. С ним API отвечает правдоподобными МОКАМИ (не реальными
 * данными репутационной базы) — чтобы можно было встроить и протестировать
 * интеграцию до оплаты. Ответы детерминированы: один и тот же адрес всегда даёт
 * один и тот же вердикт, поэтому на них можно писать стабильные тесты.
 */
const SANDBOX_KEY = 'ak_sandbox_demo_mockdata_v1';

const TIMEOUT = 30;

/**
 * Потолок ожидания при 429. Исчерпав часовое окно, сервер честно просит подождать
 * десятки минут — и клиент, слепо доверяющий заголовку Retry-After, «зависнет» на
 * всё это время. Дольше потолка не ждём, а честно сообщаем, что лимит исчерпан.
 */
const MAX_RETRY_DELAY = 120;

/**
 * Порог «протухания» вердикта в часах. Репутационная база пополняется постоянно,
 * поэтому ответ — это утверждение НА МОМЕНТ ПРОВЕРКИ.
 */
const STALE_VERDICT_HOURS = 24;

/** Ошибка API: HTTP-код разложен в человекочитаемую причину. */
final class AtloriumError extends RuntimeException
{
    private const REASONS = [
        400 => 'Ссылка не указана или не распознана (нужен адрес http/https)',
        401 => 'API-ключ отсутствует, просрочен или недействителен',
        402 => 'Недостаточно кредитов на балансе — пополните на https://atlorium.com',
        429 => 'Превышен лимит запросов — повторите позже',
        503 => 'Проверить ссылку не удалось (за сбой на своей стороне мы не списываем деньги)',
    ];

    public function __construct(public readonly int $status, string $body)
    {
        $reason = self::REASONS[$status] ?? 'Неизвестная ошибка';
        parent::__construct(sprintf(
            'HTTP %d: %s. Ответ сервера: %s',
            $status,
            $reason,
            mb_substr($body, 0, 200)
        ));
    }
}

final class UrlCheckClient
{
    private string $apiKey;
    private string $baseUrl;

    public function __construct(?string $apiKey = null, ?string $baseUrl = null)
    {
        $this->apiKey = $apiKey ?? (getenv('ATLORIUM_API_KEY') ?: SANDBOX_KEY);
        $this->baseUrl = $baseUrl ?? (getenv('ATLORIUM_BASE_URL') ?: 'https://atlorium.com');
    }

    public function isSandbox(): bool
    {
        return $this->apiKey === SANDBOX_KEY;
    }

    /**
     * GET /api/urlcheck — вердикт по одной ссылке.
     *
     * Схему можно опустить: «example.com/page» будет приведено к «http://example.com/page».
     * В ответе адрес возвращается в приведённом виде — именно в нём он и проверялся.
     *
     * @return array<string, mixed>
     */
    public function checkUrl(string $url): array
    {
        return $this->send('GET', '/api/urlcheck?' . http_build_query(['url' => $url]), null);
    }

    /**
     * POST /api/urlcheck/batch — до 100 ссылок за один вызов.
     *
     * Порядок результатов совпадает с порядком присланных ссылок. Пустые строки и
     * повторы сервер отбрасывает до проверки: повтор не добавляет работы.
     *
     * @param list<string> $urls
     * @return array<string, mixed>
     */
    public function checkUrls(array $urls): array
    {
        return $this->send('POST', '/api/urlcheck/batch', json_encode(array_values($urls), JSON_THROW_ON_ERROR));
    }

    /**
     * Отправляет запрос и один раз повторяет его на 429, если сервер просит
     * подождать разумное время.
     *
     * @return array<string, mixed>
     */
    private function send(string $method, string $path, ?string $payload): array
    {
        for ($attempt = 1; $attempt <= 2; $attempt++) {
            [$status, $body, $retryAfter] = $this->raw($method, $path, $payload);

            if ($status === 200) {
                return json_decode($body, true, 512, JSON_THROW_ON_ERROR);
            }

            $delay = ($status === 429 && $retryAfter > 0 && $retryAfter <= MAX_RETRY_DELAY) ? $retryAfter : 0;
            if ($attempt === 1 && $delay > 0) {
                sleep($delay);
                continue;
            }

            throw new AtloriumError($status, $body);
        }

        throw new RuntimeException('недостижимо');
    }

    /** @return array{0: int, 1: string, 2: int} — статус, тело, значение Retry-After */
    private function raw(string $method, string $path, ?string $payload): array
    {
        $headers = ['Authorization: Bearer ' . $this->apiKey, 'Accept: application/json'];
        if ($payload !== null) {
            $headers[] = 'Content-Type: application/json';
        }

        $curl = curl_init($this->baseUrl . $path);
        $options = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => TIMEOUT,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_HEADER => true,
            CURLOPT_CUSTOMREQUEST => $method,
        ];
        if ($payload !== null) {
            $options[CURLOPT_POSTFIELDS] = $payload;
        }
        curl_setopt_array($curl, $options);

        $response = curl_exec($curl);
        if ($response === false) {
            $error = curl_error($curl);
            curl_close($curl);
            throw new RuntimeException("Сетевая ошибка: {$error}");
        }

        $status = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        $headerSize = curl_getinfo($curl, CURLINFO_HEADER_SIZE);
        curl_close($curl);

        $rawHeaders = substr((string) $response, 0, $headerSize);
        $body = substr((string) $response, $headerSize);

        $retryAfter = 0;
        if (preg_match('/^Retry-After:\s*(\d+)/mi', $rawHeaders, $matches) === 1) {
            $retryAfter = (int) $matches[1];
        }

        return [$status, $body, $retryAfter];
    }
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

/** Категории угрозы, при которых публиковать нельзя ни при каких условиях. */
const BLOCKING_THREATS = ['social_engineering', 'malware'];

const THREAT_NAMES = [
    'social_engineering' => 'фишинг',
    'malware' => 'вредоносное ПО',
    'unwanted_software' => 'нежелательное ПО',
];

/**
 * Старше ли вердикт порога. Некорректную отметку считаем несвежей.
 *
 * Имя функции намеренно не `isStale`-подобное однословное: имена функций в PHP
 * регистронезависимы и сталкиваются со встроенными.
 */
function verdictIsStale(?string $checkedAt): bool
{
    if ($checkedAt === null || $checkedAt === '') {
        return true;
    }
    $moment = strtotime($checkedAt);
    if ($moment === false) {
        return true;
    }

    return (time() - $moment) > STALE_VERDICT_HOURS * 3600;
}

/**
 * Решает судьбу публикации по вердиктам всех ссылок в ней.
 *
 * @param list<array<string, mixed>> $results
 * @return array{decision: string, links: list<array<string, string>>, notes: list<string>}
 */
function screenUserContent(array $results): array
{
    $links = [];
    $notes = [];
    $staleClean = 0;

    foreach ($results as $result) {
        $verdict = $result['verdict'] ?? 'clean';
        $threats = $result['threatTypes'] ?? [];
        $checkedAt = $result['checkedAtUtc'] ?? '';

        if ($verdict === 'threat') {
            // threatTypes — СПИСОК: один адрес может быть отмечен сразу по
            // нескольким категориям. Разбор по первому элементу теряет остальные.
            $names = implode(', ', array_map(
                static fn (string $threat): string => THREAT_NAMES[$threat] ?? $threat,
                $threats
            ));
            $blocking = array_intersect($threats, BLOCKING_THREATS) !== [];
            $action = $blocking ? 'reject' : 'review';
            $reason = ($blocking ? 'опасная ссылка: ' : 'спорная ссылка: ') . $names;
        } elseif ($verdict === 'unknown') {
            // Вердикта нет — и это не то же самое, что «чисто». Такую строку сервис
            // не тарифицирует, а публиковать её вслепую не стоит.
            $action = 'review';
            $reason = 'вердикт получить не удалось';
        } else {
            $action = 'allow';
            $reason = 'отметок об угрозе нет';
            // Возраст важен именно у «чисто»: это единственный вердикт, на
            // основании которого мы что-то пропускаем.
            if (verdictIsStale($checkedAt)) {
                $staleClean++;
            }
        }

        $links[] = [
            'url' => (string) ($result['url'] ?? ''),
            'action' => $action,
            'reason' => $reason,
            'checkedAt' => $checkedAt !== '' ? (string) $checkedAt : '—',
        ];
    }

    $actions = array_column($links, 'action');
    $decision = 'publish';
    if (in_array('reject', $actions, true)) {
        $decision = 'reject';
    } elseif (in_array('review', $actions, true)) {
        $decision = 'hold';
    }

    if ($staleClean > 0) {
        $notes[] = sprintf(
            'Вердикт «чисто» по %d ссылке(-ам) старше суток. «Чисто» — это состояние базы '
            . 'на момент проверки, а не гарантия: перед долгой публикацией перепроверьте.',
            $staleClean
        );
    }

    return ['decision' => $decision, 'links' => $links, 'notes' => $notes];
}

// ── Демонстрация ─────────────────────────────────────────────────────────────

// Адреса из зарезервированной под примеры зоны example.com. В песочнице ветку
// ответа задаёт домен, поэтому набор ниже показывает все содержательные исходы.
const DEMO_LINKS = [
    'https://example.com/offer',
    'http://phishing.example.com/login',
    'https://unwanted.example.com/download',
    'https://danger.example.com/pay',
];

const ACTION_MARKS = ['allow' => '[ok]', 'review' => '[?]', 'reject' => '[!]'];

const VERDICT_LINE = [
    'publish' => 'ПУБЛИКОВАТЬ: опасных ссылок нет.',
    'hold' => 'НА МОДЕРАЦИЮ: есть ссылки, по которым нужен человек.',
    'reject' => 'ОТКЛОНИТЬ: в тексте есть опасные ссылки.',
];

$client = new UrlCheckClient();

if ($client->isSandbox()) {
    echo "Демо-ключ: ответы сгенерированы (моки), не реальные данные.\n\n";
}

$links = array_slice($argv, 1);
if ($links === []) {
    $links = DEMO_LINKS;
}

try {
    // Одиночная проверка — показать, как выглядит ответ по одному адресу.
    $single = $client->checkUrl($links[0]);
    // Пакетная проверка — так модерируют весь текст сразу, одним запросом.
    $batch = $client->checkUrls($links);
} catch (AtloriumError $error) {
    fwrite(STDERR, "Ошибка: {$error->getMessage()}\n");
    exit(1);
}

echo "Одиночная проверка: {$single['url']}\n";
echo "  Вердикт: {$single['verdict']} · проверено {$single['checkedAtUtc']}\n";
echo "  {$single['message']}\n\n";

printf(
    "Пакет: ссылок %d, опасных %d, без вердикта %d\n\n",
    $batch['total'],
    $batch['threatCount'],
    $batch['unknownCount']
);

$decision = screenUserContent($batch['results']);
foreach ($decision['links'] as $link) {
    echo '  ' . ACTION_MARKS[$link['action']] . " {$link['url']}\n";
    echo "       {$link['reason']} · проверено {$link['checkedAt']}\n";
}

echo "\n" . VERDICT_LINE[$decision['decision']] . "\n";
foreach ($decision['notes'] as $note) {
    echo "  [i] {$note}\n";
}

// В своём конвейере модерации решение обычно превращают в код возврата
// (reject — ненулевой), чтобы шаг падал сам и публикация не уходила дальше.
// Пример этого не делает намеренно: демо-набор ссылок заведомо содержит
// опасные, и прогон примеров падал бы на каждом запуске.
