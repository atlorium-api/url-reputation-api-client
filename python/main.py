"""
Клиент API проверки ссылки Atlorium — репутация URL: фишинг, вредонос, нежелательное ПО.

Запуск (работает сразу, без регистрации — на демо-ключе):
    pip install -r requirements.txt
    python main.py

Боевой ключ: получить на https://atlorium.com и положить в переменную окружения
ATLORIUM_API_KEY. Код при этом не меняется.
"""

import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

import requests

# Публичный демо-ключ. С ним API отвечает правдоподобными МОКАМИ (не реальными
# данными репутационной базы) — чтобы можно было встроить и протестировать
# интеграцию до оплаты. Ответы детерминированы: один и тот же адрес всегда даёт
# один и тот же вердикт, поэтому на них можно писать стабильные тесты.
SANDBOX_KEY = "ak_sandbox_demo_mockdata_v1"

API_KEY = os.environ.get("ATLORIUM_API_KEY", SANDBOX_KEY)
BASE_URL = os.environ.get("ATLORIUM_BASE_URL", "https://atlorium.com")

TIMEOUT = 30

# Потолок ожидания при 429. Исчерпав часовое окно, сервер честно просит подождать
# десятки минут — и клиент, слепо доверяющий заголовку Retry-After, «зависнет» на
# всё это время. Дольше потолка не ждём, а честно сообщаем, что лимит исчерпан.
MAX_RETRY_DELAY = 120

# Порог «протухания» вердикта. Репутационная база пополняется постоянно, поэтому
# ответ — это утверждение НА МОМЕНТ ПРОВЕРКИ. Для ссылки, которая будет висеть
# на странице неделями, вердикт «чисто» суточной давности стоит перепроверить.
STALE_VERDICT_HOURS = 24


class AtloriumError(RuntimeError):
    """Ошибка API. Код HTTP разложен в человекочитаемую причину."""

    REASONS = {
        400: "Ссылка не указана или не распознана (нужен адрес http/https)",
        401: "API-ключ отсутствует, просрочен или недействителен",
        402: "Недостаточно кредитов на балансе — пополните на https://atlorium.com",
        429: "Превышен лимит запросов — повторите позже",
        503: "Проверить ссылку не удалось (за сбой на своей стороне мы не списываем деньги)",
    }

    def __init__(self, status: int, body: str):
        reason = self.REASONS.get(status, "Неизвестная ошибка")
        super().__init__(f"HTTP {status}: {reason}. Ответ сервера: {body[:200]}")
        self.status = status


def _retry_after(response: requests.Response) -> int:
    """Сколько ждать по заголовку Retry-After, но не дольше потолка. 0 — не ждать."""
    try:
        seconds = int(response.headers.get("Retry-After", ""))
    except ValueError:
        return 0
    return seconds if 0 < seconds <= MAX_RETRY_DELAY else 0


def _request(method: str, path: str, *, params: dict | None = None, json: object = None) -> dict:
    url = f"{BASE_URL}{path}"
    headers = {"Authorization": f"Bearer {API_KEY}", "Accept": "application/json"}

    for attempt in (1, 2):
        response = requests.request(
            method, url, params=params, json=json, headers=headers, timeout=TIMEOUT
        )
        if response.ok:
            return response.json()

        # Один повтор на 429 — и только если сервер просит подождать разумное время.
        delay = _retry_after(response) if response.status_code == 429 else 0
        if attempt == 1 and delay:
            time.sleep(delay)
            continue
        raise AtloriumError(response.status_code, response.text)

    raise AssertionError("недостижимо")


def check_url(url: str) -> dict:
    """GET /api/urlcheck — вердикт по одной ссылке.

    Схему можно опустить: «example.com/page» будет приведено к «http://example.com/page».
    В ответе адрес возвращается в приведённом виде — именно в нём он и проверялся.
    """
    return _request("GET", "/api/urlcheck", params={"url": url})


def check_urls(urls: list[str]) -> dict:
    """POST /api/urlcheck/batch — до 100 ссылок за один вызов.

    Порядок результатов совпадает с порядком присланных ссылок. Пустые строки и
    повторы сервер отбрасывает до проверки: повтор не добавляет работы.
    """
    return _request("POST", "/api/urlcheck/batch", json=urls)


# ── Применение данных: модерация ссылок в пользовательском контенте ───────────
# Вердикт сам по себе — просто строка. Ценность появляется, когда по нему
# принимают решение о публикации. Ниже — правила, по которым объявление,
# комментарий или сообщение в чате пропускают, отправляют модератору или
# отклоняют.
#
# Правила намеренно разные для разных категорий угрозы:
#   * фишинг и вредонос — прямой ущерб посетителю, публиковать нельзя;
#   * нежелательное ПО — граница размытая, решает человек;
#   * вердикта нет — «не проверено» не равно «безопасно», тоже к человеку.


@dataclass
class LinkDecision:
    url: str
    action: str  # allow | review | reject
    reason: str
    checked_at: str


@dataclass
class ContentDecision:
    decision: str  # publish | hold | reject
    links: list[LinkDecision] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


# Категории угрозы, при которых публиковать нельзя ни при каких условиях.
BLOCKING_THREATS = {"social_engineering", "malware"}

THREAT_NAMES = {
    "social_engineering": "фишинг",
    "malware": "вредоносное ПО",
    "unwanted_software": "нежелательное ПО",
}


def _is_stale(checked_at: str | None) -> bool:
    """Старше ли вердикт порога. Некорректную отметку считаем несвежей."""
    if not checked_at:
        return True
    try:
        moment = datetime.fromisoformat(checked_at.replace("Z", "+00:00"))
    except ValueError:
        return True
    return (datetime.now(timezone.utc) - moment).total_seconds() > STALE_VERDICT_HOURS * 3600


def screen_user_content(results: list[dict]) -> ContentDecision:
    """Решает судьбу публикации по вердиктам всех ссылок в ней."""
    decision = ContentDecision(decision="publish")
    stale_clean = 0

    for result in results:
        url = result.get("url", "")
        verdict = result.get("verdict")
        threats = result.get("threatTypes") or []
        checked_at = result.get("checkedAtUtc") or "—"

        if verdict == "threat":
            # threatTypes — СПИСОК: один адрес может быть отмечен сразу по
            # нескольким категориям. Разбор по первому элементу теряет остальные.
            names = ", ".join(THREAT_NAMES.get(t, t) for t in threats)
            action = "reject" if BLOCKING_THREATS.intersection(threats) else "review"
            reason = ("опасная ссылка: " if action == "reject" else "спорная ссылка: ") + names
        elif verdict == "unknown":
            # Вердикта нет — и это не то же самое, что «чисто». Такую строку
            # сервис не тарифицирует, а публиковать её вслепую не стоит.
            action, reason = "review", "вердикт получить не удалось"
        else:
            action, reason = "allow", "отметок об угрозе нет"
            # Возраст важен именно у «чисто»: это единственный вердикт, на
            # основании которого мы что-то пропускаем.
            if _is_stale(result.get("checkedAtUtc")):
                stale_clean += 1

        decision.links.append(LinkDecision(url, action, reason, checked_at))

    actions = {link.action for link in decision.links}
    if "reject" in actions:
        decision.decision = "reject"
    elif "review" in actions:
        decision.decision = "hold"

    if stale_clean:
        decision.notes.append(
            f"Вердикт «чисто» по {stale_clean} ссылке(-ам) старше суток. «Чисто» — это "
            "состояние базы на момент проверки, а не гарантия: перед долгой публикацией перепроверьте."
        )

    return decision


# ── Демонстрация ─────────────────────────────────────────────────────────────

# Адреса из зарезервированной под примеры зоны example.com. В песочнице ветку
# ответа задаёт домен, поэтому набор ниже показывает все содержательные исходы.
DEMO_LINKS = [
    "https://example.com/offer",
    "http://phishing.example.com/login",
    "https://unwanted.example.com/download",
    "https://danger.example.com/pay",
]

ACTION_MARKS = {"allow": "[ok]", "review": "[?]", "reject": "[!]"}

VERDICT_LINE = {
    "publish": "ПУБЛИКОВАТЬ: опасных ссылок нет.",
    "hold": "НА МОДЕРАЦИЮ: есть ссылки, по которым нужен человек.",
    "reject": "ОТКЛОНИТЬ: в тексте есть опасные ссылки.",
}


def main() -> int:
    if API_KEY == SANDBOX_KEY:
        print("Демо-ключ: ответы сгенерированы (моки), не реальные данные.\n")

    links = sys.argv[1:] or DEMO_LINKS

    try:
        # Одиночная проверка — показать, как выглядит ответ по одному адресу.
        single = check_url(links[0])
        print(f"Одиночная проверка: {single['url']}")
        print(f"  Вердикт: {single['verdict']} · проверено {single['checkedAtUtc']}")
        print(f"  {single['message']}\n")

        # Пакетная проверка — так модерируют весь текст сразу, одним запросом.
        batch = check_urls(links)
    except AtloriumError as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 1

    print(f"Пакет: ссылок {batch['total']}, опасных {batch['threatCount']}, "
          f"без вердикта {batch['unknownCount']}\n")

    decision = screen_user_content(batch["results"])
    for link in decision.links:
        print(f"  {ACTION_MARKS[link.action]} {link.url}")
        print(f"       {link.reason} · проверено {link.checked_at}")

    print(f"\n{VERDICT_LINE[decision.decision]}")
    for note in decision.notes:
        print(f"  [i] {note}")

    # В своём конвейере модерации решение обычно превращают в код возврата
    # (reject — ненулевой), чтобы шаг падал сам и публикация не уходила дальше.
    # Пример этого не делает намеренно: демо-набор ссылок заведомо содержит
    # опасные, и прогон примеров падал бы на каждом запуске.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
