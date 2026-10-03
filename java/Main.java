/*
 * Клиент API проверки ссылки Atlorium — репутация URL: фишинг, вредонос,
 * нежелательное ПО.
 *
 * Запуск (работает сразу, без регистрации — на демо-ключе).
 * Начиная с Java 11 файл запускается напрямую, без компиляции и без зависимостей:
 *
 *     java Main.java
 *
 * Боевой ключ: получить на https://atlorium.com и положить в переменную окружения
 * ATLORIUM_API_KEY. Код при этом не меняется.
 */

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class Main {

    /**
     * Публичный демо-ключ. С ним API отвечает правдоподобными МОКАМИ (не реальными
     * данными репутационной базы) — чтобы можно было встроить и протестировать
     * интеграцию до оплаты. Ответы детерминированы: один и тот же адрес всегда даёт
     * один и тот же вердикт, поэтому на них можно писать стабильные тесты.
     */
    static final String SANDBOX_KEY = "ak_sandbox_demo_mockdata_v1";

    static final String API_KEY = envOr("ATLORIUM_API_KEY", SANDBOX_KEY);
    static final String BASE_URL = envOr("ATLORIUM_BASE_URL", "https://atlorium.com");

    /**
     * Потолок ожидания при 429. Исчерпав часовое окно, сервер честно просит подождать
     * десятки минут — и клиент, слепо доверяющий заголовку Retry-After, «зависнет» на
     * всё это время. Дольше потолка не ждём, а честно сообщаем, что лимит исчерпан.
     */
    static final int MAX_RETRY_DELAY_S = 120;

    /**
     * Порог «протухания» вердикта. Репутационная база пополняется постоянно, поэтому
     * ответ — это утверждение НА МОМЕНТ ПРОВЕРКИ.
     */
    static final long STALE_VERDICT_HOURS = 24;

    static final HttpClient CLIENT = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(30))
            .build();

    static String envOr(String key, String fallback) {
        String value = System.getenv(key);
        return (value == null || value.isBlank()) ? fallback : value;
    }

    /** Ошибка API: HTTP-код разложен в человекочитаемую причину. */
    static class AtloriumException extends RuntimeException {
        private static final Map<Integer, String> REASONS = Map.of(
                400, "Ссылка не указана или не распознана (нужен адрес http/https)",
                401, "API-ключ отсутствует, просрочен или недействителен",
                402, "Недостаточно кредитов на балансе — пополните на https://atlorium.com",
                429, "Превышен лимит запросов — повторите позже",
                503, "Проверить ссылку не удалось (за сбой на своей стороне мы не списываем деньги)");

        final int status;

        AtloriumException(int status, String body) {
            super("HTTP " + status + ": "
                    + REASONS.getOrDefault(status, "Неизвестная ошибка")
                    + ". Ответ сервера: " + body.substring(0, Math.min(200, body.length())));
            this.status = status;
        }
    }

    /** Сколько секунд ждать по заголовку Retry-After, но не дольше потолка. 0 — не ждать. */
    static int retryAfter(HttpResponse<String> response) {
        int seconds = response.headers().firstValue("Retry-After")
                .map(value -> {
                    try {
                        return Integer.parseInt(value.trim());
                    } catch (NumberFormatException error) {
                        return 0;
                    }
                })
                .orElse(0);
        return (seconds > 0 && seconds <= MAX_RETRY_DELAY_S) ? seconds : 0;
    }

    static String send(String method, String path, String query, String payload)
            throws IOException, InterruptedException {
        String url = BASE_URL + path + (query.isEmpty() ? "" : "?" + query);

        for (int attempt = 1; attempt <= 2; attempt++) {
            HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url))
                    .header("Authorization", "Bearer " + API_KEY)
                    .header("Accept", "application/json")
                    .timeout(Duration.ofSeconds(30));

            if (payload == null) {
                builder = builder.GET();
            } else {
                builder = builder.header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(payload, StandardCharsets.UTF_8));
            }

            HttpResponse<String> response = CLIENT.send(builder.build(),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

            if (response.statusCode() == 200) {
                return response.body();
            }

            // Один повтор на 429 — и только если сервер просит подождать разумное время.
            int delay = response.statusCode() == 429 ? retryAfter(response) : 0;
            if (attempt == 1 && delay > 0) {
                Thread.sleep(delay * 1000L);
                continue;
            }
            throw new AtloriumException(response.statusCode(), response.body());
        }

        throw new IllegalStateException("недостижимо");
    }

    /**
     * GET /api/urlcheck — вердикт по одной ссылке.
     *
     * Схему можно опустить: «example.com/page» будет приведено к «http://example.com/page».
     * В ответе адрес возвращается в приведённом виде — именно в нём он и проверялся.
     */
    static String checkUrl(String link) throws IOException, InterruptedException {
        return send("GET", "/api/urlcheck", "url=" + URLEncoder.encode(link, StandardCharsets.UTF_8), null);
    }

    /**
     * POST /api/urlcheck/batch — до 100 ссылок за один вызов.
     *
     * Порядок результатов совпадает с порядком присланных ссылок. Пустые строки и
     * повторы сервер отбрасывает до проверки: повтор не добавляет работы.
     */
    static String checkUrls(List<String> links) throws IOException, InterruptedException {
        String payload = links.stream()
                .map(link -> "\"" + link.replace("\\", "\\\\").replace("\"", "\\\"") + "\"")
                .collect(Collectors.joining(",", "[", "]"));
        return send("POST", "/api/urlcheck/batch", "", payload);
    }

    // ── Разбор JSON ──────────────────────────────────────────────────────────
    // Пример намеренно оставлен без внешних зависимостей, чтобы запускаться одной
    // командой `java Main.java`. В рабочем проекте берите Jackson или Gson и
    // маппьте ответ в полноценную запись — эти регулярки существуют только ради
    // отсутствия pom.xml.

    /** Режет массив results на отдельные объекты по балансу фигурных скобок. */
    static List<String> splitResults(String json) {
        List<String> objects = new ArrayList<>();
        int start = json.indexOf("\"results\"");
        if (start < 0) {
            return objects;
        }
        int depth = 0;
        int from = -1;
        for (int i = json.indexOf('[', start); i >= 0 && i < json.length(); i++) {
            char symbol = json.charAt(i);
            if (symbol == '{') {
                if (depth == 0) {
                    from = i;
                }
                depth++;
            } else if (symbol == '}') {
                depth--;
                if (depth == 0 && from >= 0) {
                    objects.add(json.substring(from, i + 1));
                }
            } else if (symbol == ']' && depth == 0) {
                break;
            }
        }
        return objects;
    }

    static String str(String json, String field) {
        Matcher matcher = Pattern.compile("\"" + field + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"").matcher(json);
        return matcher.find() ? matcher.group(1).replace("\\\"", "\"") : null;
    }

    static int number(String json, String field) {
        Matcher matcher = Pattern.compile("\"" + field + "\"\\s*:\\s*(-?\\d+)").matcher(json);
        return matcher.find() ? Integer.parseInt(matcher.group(1)) : 0;
    }

    /** Значения строкового массива, например threatTypes. */
    static List<String> strings(String json, String field) {
        Matcher matcher = Pattern.compile("\"" + field + "\"\\s*:\\s*\\[([^\\]]*)\\]").matcher(json);
        if (!matcher.find() || matcher.group(1).isBlank()) {
            return List.of();
        }
        return Arrays.stream(matcher.group(1).split(","))
                .map(item -> item.trim().replace("\"", ""))
                .filter(item -> !item.isEmpty())
                .collect(Collectors.toList());
    }

    // ── Применение данных: модерация ссылок в пользовательском контенте ──────
    // Вердикт сам по себе — просто строка. Ценность появляется, когда по нему
    // принимают решение о публикации. Ниже — правила, по которым объявление,
    // комментарий или сообщение в чате пропускают, отправляют модератору или
    // отклоняют.
    //
    // Правила намеренно разные для разных категорий угрозы:
    //   * фишинг и вредонос — прямой ущерб посетителю, публиковать нельзя;
    //   * нежелательное ПО — граница размытая, решает человек;
    //   * вердикта нет — «не проверено» не равно «безопасно», тоже к человеку.

    record LinkDecision(String url, String action, String reason, String checkedAt) {
    }

    record ContentDecision(String decision, List<LinkDecision> links, List<String> notes) {
    }

    /** Категории угрозы, при которых публиковать нельзя ни при каких условиях. */
    static final Set<String> BLOCKING_THREATS = Set.of("social_engineering", "malware");

    static final Map<String, String> THREAT_NAMES = Map.of(
            "social_engineering", "фишинг",
            "malware", "вредоносное ПО",
            "unwanted_software", "нежелательное ПО");

    /** Старше ли вердикт порога. Некорректную отметку считаем несвежей. */
    static boolean isStale(String checkedAt) {
        if (checkedAt == null || checkedAt.isBlank()) {
            return true;
        }
        try {
            return Instant.parse(checkedAt).isBefore(Instant.now().minus(Duration.ofHours(STALE_VERDICT_HOURS)));
        } catch (DateTimeParseException error) {
            return true;
        }
    }

    static ContentDecision screenUserContent(List<String> results) {
        List<LinkDecision> links = new ArrayList<>();
        List<String> notes = new ArrayList<>();
        int staleClean = 0;

        for (String result : results) {
            String verdict = str(result, "verdict");
            String rawCheckedAt = str(result, "checkedAtUtc");
            String checkedAt = (rawCheckedAt == null || rawCheckedAt.isBlank()) ? "—" : rawCheckedAt;

            String action;
            String reason;

            if ("threat".equals(verdict)) {
                // threatTypes — СПИСОК: один адрес может быть отмечен сразу по
                // нескольким категориям. Разбор по первому элементу теряет остальные.
                List<String> threats = strings(result, "threatTypes");
                String names = threats.stream()
                        .map(threat -> THREAT_NAMES.getOrDefault(threat, threat))
                        .collect(Collectors.joining(", "));
                boolean blocking = threats.stream().anyMatch(BLOCKING_THREATS::contains);
                action = blocking ? "reject" : "review";
                reason = (blocking ? "опасная ссылка: " : "спорная ссылка: ") + names;
            } else if ("unknown".equals(verdict)) {
                // Вердикта нет — и это не то же самое, что «чисто». Такую строку сервис
                // не тарифицирует, а публиковать её вслепую не стоит.
                action = "review";
                reason = "вердикт получить не удалось";
            } else {
                action = "allow";
                reason = "отметок об угрозе нет";
                // Возраст важен именно у «чисто»: это единственный вердикт, на
                // основании которого мы что-то пропускаем.
                if (isStale(rawCheckedAt)) {
                    staleClean++;
                }
            }

            links.add(new LinkDecision(str(result, "url"), action, reason, checkedAt));
        }

        String decision = "publish";
        if (links.stream().anyMatch(link -> "reject".equals(link.action()))) {
            decision = "reject";
        } else if (links.stream().anyMatch(link -> "review".equals(link.action()))) {
            decision = "hold";
        }

        if (staleClean > 0) {
            notes.add("Вердикт «чисто» по " + staleClean + " ссылке(-ам) старше суток. «Чисто» — это "
                    + "состояние базы на момент проверки, а не гарантия: перед долгой публикацией перепроверьте.");
        }

        return new ContentDecision(decision, links, notes);
    }

    // ── Демонстрация ─────────────────────────────────────────────────────────

    /**
     * Адреса из зарезервированной под примеры зоны example.com. В песочнице ветку
     * ответа задаёт домен, поэтому набор ниже показывает все содержательные исходы.
     */
    static final List<String> DEMO_LINKS = List.of(
            "https://example.com/offer",
            "http://phishing.example.com/login",
            "https://unwanted.example.com/download",
            "https://danger.example.com/pay");

    static final Map<String, String> ACTION_MARKS = Map.of(
            "allow", "[ok]", "review", "[?]", "reject", "[!]");

    static final Map<String, String> VERDICT_LINE = Map.of(
            "publish", "ПУБЛИКОВАТЬ: опасных ссылок нет.",
            "hold", "НА МОДЕРАЦИЮ: есть ссылки, по которым нужен человек.",
            "reject", "ОТКЛОНИТЬ: в тексте есть опасные ссылки.");

    public static void main(String[] args) throws Exception {
        if (API_KEY.equals(SANDBOX_KEY)) {
            System.out.println("Демо-ключ: ответы сгенерированы (моки), не реальные данные.\n");
        }

        List<String> links = args.length > 0 ? Arrays.asList(args) : DEMO_LINKS;

        String single;
        String batch;
        try {
            // Одиночная проверка — показать, как выглядит ответ по одному адресу.
            single = checkUrl(links.get(0));
            // Пакетная проверка — так модерируют весь текст сразу, одним запросом.
            batch = checkUrls(links);
        } catch (AtloriumException error) {
            System.err.println("Ошибка: " + error.getMessage());
            System.exit(1);
            return;
        }

        System.out.println("Одиночная проверка: " + str(single, "url"));
        System.out.println("  Вердикт: " + str(single, "verdict") + " · проверено " + str(single, "checkedAtUtc"));
        System.out.println("  " + str(single, "message") + "\n");

        System.out.println("Пакет: ссылок " + number(batch, "total")
                + ", опасных " + number(batch, "threatCount")
                + ", без вердикта " + number(batch, "unknownCount") + "\n");

        ContentDecision decision = screenUserContent(splitResults(batch));
        for (LinkDecision link : decision.links()) {
            System.out.println("  " + ACTION_MARKS.get(link.action()) + " " + link.url());
            System.out.println("       " + link.reason() + " · проверено " + link.checkedAt());
        }

        System.out.println("\n" + VERDICT_LINE.get(decision.decision()));
        for (String note : decision.notes()) {
            System.out.println("  [i] " + note);
        }

        // В своём конвейере модерации решение обычно превращают в код возврата
        // (reject — ненулевой), чтобы шаг падал сам и публикация не уходила дальше.
        // Пример этого не делает намеренно: демо-набор ссылок заведомо содержит
        // опасные, и прогон примеров падал бы на каждом запуске.
    }
}
