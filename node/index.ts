/**
 * Клиент API проверки ссылки Atlorium — репутация URL: фишинг, вредонос, нежелательное ПО.
 *
 * Запуск (работает сразу, без регистрации — на демо-ключе):
 *   npm install
 *   npm start
 *
 * Боевой ключ: получить на https://atlorium.com и положить в переменную окружения
 * ATLORIUM_API_KEY. Код при этом не меняется.
 */

/**
 * Публичный демо-ключ. С ним API отвечает правдоподобными МОКАМИ (не реальными
 * данными репутационной базы) — чтобы можно было встроить и протестировать
 * интеграцию до оплаты. Ответы детерминированы: один и тот же адрес всегда даёт
 * один и тот же вердикт, поэтому на них можно писать стабильные тесты.
 */
const SANDBOX_KEY = 'ak_sandbox_demo_mockdata_v1';

const API_KEY = process.env.ATLORIUM_API_KEY ?? SANDBOX_KEY;
const BASE_URL = process.env.ATLORIUM_BASE_URL ?? 'https://atlorium.com';

const TIMEOUT_MS = 30_000;

/**
 * Потолок ожидания при 429. Исчерпав часовое окно, сервер честно просит подождать
 * десятки минут — и клиент, слепо доверяющий заголовку Retry-After, «зависнет» на
 * всё это время. Дольше потолка не ждём, а честно сообщаем, что лимит исчерпан.
 */
const MAX_RETRY_DELAY_S = 120;

/**
 * Порог «протухания» вердикта. Репутационная база пополняется постоянно, поэтому
 * ответ — это утверждение НА МОМЕНТ ПРОВЕРКИ. Для ссылки, которая будет висеть
 * на странице неделями, вердикт «чисто» суточной давности стоит перепроверить.
 */
const STALE_VERDICT_HOURS = 24;

/** Категория угрозы, которой отмечен адрес. */
export type ThreatType = 'malware' | 'social_engineering' | 'unwanted_software';

/** Итог проверки: чисто, угроза или вердикт получить не удалось. */
export type Verdict = 'clean' | 'threat' | 'unknown';

/** Вердикт по одной ссылке. */
export interface UrlThreatResult {
  /** Адрес в приведённом виде — именно в нём он и проверялся. */
  url: string;
  verdict: Verdict;
  /** Список категорий: один адрес может быть отмечен сразу по нескольким. */
  threatTypes: ThreatType[];
  /** Момент проверки. Показывайте его рядом с вердиктом: он датирует утверждение. */
  checkedAtUtc: string;
  message: string;
  elapsedMs: number;
}

/** Ответ пакетной проверки. */
export interface UrlThreatBatchResponse {
  /** Вердикты в том же порядке, в каком были присланы ссылки. */
  results: UrlThreatResult[];
  total: number;
  threatCount: number;
  /** Сколько строк осталось без вердикта. Они не тарифицируются. */
  unknownCount: number;
  elapsedMs: number;
}

const ERROR_REASONS: Record<number, string> = {
  400: 'Ссылка не указана или не распознана (нужен адрес http/https)',
  401: 'API-ключ отсутствует, просрочен или недействителен',
  402: 'Недостаточно кредитов на балансе — пополните на https://atlorium.com',
  429: 'Превышен лимит запросов — повторите позже',
  503: 'Проверить ссылку не удалось (за сбой на своей стороне мы не списываем деньги)',
};

/** Ошибка API: HTTP-код разложен в человекочитаемую причину. */
export class AtloriumError extends Error {
  constructor(readonly status: number, body: string) {
    const reason = ERROR_REASONS[status] ?? 'Неизвестная ошибка';
    super(`HTTP ${status}: ${reason}. Ответ сервера: ${body.slice(0, 200)}`);
    this.name = 'AtloriumError';
  }
}

/** Сколько ждать по заголовку Retry-After, но не дольше потолка. 0 — не ждать. */
function retryAfter(response: Response): number {
  const seconds = Number.parseInt(response.headers.get('Retry-After') ?? '', 10);
  if (!Number.isFinite(seconds) || seconds <= 0) return 0;
  return seconds <= MAX_RETRY_DELAY_S ? seconds : 0;
}

const sleep = (seconds: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, seconds * 1000));

async function request<T>(path: string, init: RequestInit, params: Record<string, string> = {}): Promise<T> {
  const url = new URL(path, BASE_URL);
  for (const [key, value] of Object.entries(params)) {
    url.searchParams.set(key, value);
  }

  for (let attempt = 1; attempt <= 2; attempt += 1) {
    const response = await fetch(url, {
      ...init,
      headers: {
        Authorization: `Bearer ${API_KEY}`,
        Accept: 'application/json',
        ...(init.body ? { 'Content-Type': 'application/json' } : {}),
      },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });

    if (response.ok) {
      return (await response.json()) as T;
    }

    // Один повтор на 429 — и только если сервер просит подождать разумное время.
    const delay = response.status === 429 ? retryAfter(response) : 0;
    if (attempt === 1 && delay > 0) {
      await sleep(delay);
      continue;
    }
    throw new AtloriumError(response.status, await response.text());
  }

  throw new Error('недостижимо');
}

/**
 * GET /api/urlcheck — вердикт по одной ссылке.
 *
 * Схему можно опустить: «example.com/page» будет приведено к «http://example.com/page».
 * В ответе адрес возвращается в приведённом виде — именно в нём он и проверялся.
 */
export async function checkUrl(url: string): Promise<UrlThreatResult> {
  return request<UrlThreatResult>('/api/urlcheck', { method: 'GET' }, { url });
}

/**
 * POST /api/urlcheck/batch — до 100 ссылок за один вызов.
 *
 * Порядок результатов совпадает с порядком присланных ссылок. Пустые строки и
 * повторы сервер отбрасывает до проверки: повтор не добавляет работы.
 */
export async function checkUrls(urls: string[]): Promise<UrlThreatBatchResponse> {
  return request<UrlThreatBatchResponse>('/api/urlcheck/batch', {
    method: 'POST',
    body: JSON.stringify(urls),
  });
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

export type LinkAction = 'allow' | 'review' | 'reject';
export type ContentAction = 'publish' | 'hold' | 'reject';

export interface LinkDecision {
  url: string;
  action: LinkAction;
  reason: string;
  checkedAt: string;
}

export interface ContentDecision {
  decision: ContentAction;
  links: LinkDecision[];
  notes: string[];
}

/** Категории угрозы, при которых публиковать нельзя ни при каких условиях. */
const BLOCKING_THREATS: ReadonlySet<string> = new Set<ThreatType>(['social_engineering', 'malware']);

const THREAT_NAMES: Record<string, string> = {
  social_engineering: 'фишинг',
  malware: 'вредоносное ПО',
  unwanted_software: 'нежелательное ПО',
};

/** Старше ли вердикт порога. Некорректную отметку считаем несвежей. */
function isStale(checkedAt: string | undefined): boolean {
  if (!checkedAt) return true;
  const moment = Date.parse(checkedAt);
  if (Number.isNaN(moment)) return true;
  return Date.now() - moment > STALE_VERDICT_HOURS * 3600 * 1000;
}

export function screenUserContent(results: UrlThreatResult[]): ContentDecision {
  const links: LinkDecision[] = [];
  const notes: string[] = [];
  let staleClean = 0;

  for (const result of results) {
    const threats = result.threatTypes ?? [];
    const checkedAt = result.checkedAtUtc || '—';
    let action: LinkAction;
    let reason: string;

    if (result.verdict === 'threat') {
      // threatTypes — СПИСОК: один адрес может быть отмечен сразу по нескольким
      // категориям. Разбор по первому элементу теряет остальные.
      const names = threats.map((threat) => THREAT_NAMES[threat] ?? threat).join(', ');
      action = threats.some((threat) => BLOCKING_THREATS.has(threat)) ? 'reject' : 'review';
      reason = `${action === 'reject' ? 'опасная ссылка: ' : 'спорная ссылка: '}${names}`;
    } else if (result.verdict === 'unknown') {
      // Вердикта нет — и это не то же самое, что «чисто». Такую строку сервис
      // не тарифицирует, а публиковать её вслепую не стоит.
      action = 'review';
      reason = 'вердикт получить не удалось';
    } else {
      action = 'allow';
      reason = 'отметок об угрозе нет';
      // Возраст важен именно у «чисто»: это единственный вердикт, на основании
      // которого мы что-то пропускаем.
      if (isStale(result.checkedAtUtc)) staleClean += 1;
    }

    links.push({ url: result.url, action, reason, checkedAt });
  }

  let decision: ContentAction = 'publish';
  if (links.some((link) => link.action === 'reject')) decision = 'reject';
  else if (links.some((link) => link.action === 'review')) decision = 'hold';

  if (staleClean > 0) {
    notes.push(
      `Вердикт «чисто» по ${staleClean} ссылке(-ам) старше суток. «Чисто» — это состояние базы ` +
        'на момент проверки, а не гарантия: перед долгой публикацией перепроверьте.',
    );
  }

  return { decision, links, notes };
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

const ACTION_MARKS: Record<LinkAction, string> = { allow: '[ok]', review: '[?]', reject: '[!]' };

const VERDICT_LINE: Record<ContentAction, string> = {
  publish: 'ПУБЛИКОВАТЬ: опасных ссылок нет.',
  hold: 'НА МОДЕРАЦИЮ: есть ссылки, по которым нужен человек.',
  reject: 'ОТКЛОНИТЬ: в тексте есть опасные ссылки.',
};

async function main(): Promise<void> {
  if (API_KEY === SANDBOX_KEY) {
    console.log('Демо-ключ: ответы сгенерированы (моки), не реальные данные.\n');
  }

  const args = process.argv.slice(2);
  const links = args.length > 0 ? args : DEMO_LINKS;

  // Одиночная проверка — показать, как выглядит ответ по одному адресу.
  const single = await checkUrl(links[0]!);
  console.log(`Одиночная проверка: ${single.url}`);
  console.log(`  Вердикт: ${single.verdict} · проверено ${single.checkedAtUtc}`);
  console.log(`  ${single.message}\n`);

  // Пакетная проверка — так модерируют весь текст сразу, одним запросом.
  const batch = await checkUrls(links);
  console.log(
    `Пакет: ссылок ${batch.total}, опасных ${batch.threatCount}, без вердикта ${batch.unknownCount}\n`,
  );

  const decision = screenUserContent(batch.results);
  for (const link of decision.links) {
    console.log(`  ${ACTION_MARKS[link.action]} ${link.url}`);
    console.log(`       ${link.reason} · проверено ${link.checkedAt}`);
  }

  console.log(`\n${VERDICT_LINE[decision.decision]}`);
  for (const note of decision.notes) {
    console.log(`  [i] ${note}`);
  }

  // В своём конвейере модерации решение обычно превращают в код возврата
  // (reject — ненулевой), чтобы шаг падал сам и публикация не уходила дальше.
  // Пример этого не делает намеренно: демо-набор ссылок заведомо содержит
  // опасные, и прогон примеров падал бы на каждом запуске.
}

// Запуск только когда файл выполняется напрямую, а не импортируется.
if (process.argv[1]?.includes('index')) {
  main().catch((error: unknown) => {
    console.error('Ошибка:', error instanceof Error ? error.message : error);
    process.exit(1);
  });
}
