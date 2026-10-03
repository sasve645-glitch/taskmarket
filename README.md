# TaskMarket — серверна версія

## Що додано
- PostgreSQL база даних
- безпечне хешування паролів через bcrypt
- JWT авторизація
- API реєстрації та входу
- API профілю
- API завдань
- створення завдань записується в БД
- список завдань завантажується з БД

## Запуск локально

Потрібні Node.js 18+ та PostgreSQL.

1. Створи базу PostgreSQL.
2. Скопіюй `.env.example` у `.env` та впиши DATABASE_URL і JWT_SECRET.
3. Встанови залежності:
   npm install
4. Запусти:
   npm start
5. Відкрий:
   http://localhost:3000

Таблиці створюються автоматично при запуску.

## Важливо
Не публікуй `.env` і не використовуй стандартний JWT_SECRET у production.
Для реального запуску в інтернеті потрібен хостинг Node.js і PostgreSQL (наприклад, Render/Railway + PostgreSQL або інший сумісний хостинг).


## Реальні TON/USDT платежі

Платежі використовують TON Connect: гаманець користувача сам підписує транзакцію, а приватний ключ до сайту не передається. Для TON використовується ваш приймальний гаманець, а USDT — офіційний USDT Jetton у TON.

Перед запуском:
1. Розгорни сайт на HTTPS-домені.
2. У `public/tonconnect-manifest.json` заміни `YOUR-DOMAIN.example` на реальний домен.
3. Встанови `.env`.
4. Для стабільного production-моніторингу отримай API key TON Center і вкажи `TON_API_KEY`.
5. Перевір платежі спочатку на testnet/малих сумах.

**Важливо:** поточний MVP зараховує `requested_amount` у внутрішній баланс як умовну USD-одиницю. Для production-гаманця потрібна окрема бухгалтерська книга (ledger), фіксація курсу, confirmations/finality, захист від повторного зарахування та повноцінний withdrawal-модуль. Не зберігай seed/private key на сервері.


### TON / USDT balance
Тепер акаунт має окремі `ton_balance` та `usdt_balance`, а також endpoint історії `/api/payments/history`.
