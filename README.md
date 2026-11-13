# Personal Finance Tracker

A browser rebuild of a Python/Tkinter + SQLite desktop finance tracker.
Register a local account, record income and expenses, and see where the money
goes. There is no backend — everything is stored in the browser.

## Features

- **Local accounts** — register or sign in. Passwords are salted and hashed
  with PBKDF2 through the Web Crypto API.
- **Transactions** — add, edit and delete income and expense entries with a
  category, date, amount and optional note.
- **Overview** — all-time balance plus this month's income, spending and a
  spending-by-category breakdown.
- **Filters** — search by category or note and filter by type, category or
  month, with live totals for the filtered set.
- **Demo data** — one click creates a local `demo` account with three months of
  sample transactions.

## Files

```
finance-tracker/
├── index.html   — the whole app (auth screen + dashboard)
├── styles.css   — standalone stylesheet, no other CSS needed
├── app.js       — storage, authentication, CRUD, filters and rendering
└── README.md
```

## Running it

Open `index.html` in a browser, or use the **Live Server** extension in VS Code
and open it from this folder.

No build step, no dependencies, no database server.

## Demo account

Use **Explore with demo data** on the sign-in screen. The demo account is
`demo` / `demo1234`, created automatically on your device the first time.

## Data and security

- Accounts and transactions are saved in `localStorage` under the key
  `finance-tracker:v1`.
- Nothing is uploaded anywhere. Clearing browser data removes everything.
- Amounts are stored in cents to avoid floating-point rounding errors.
- This is a front-end demo, not a real banking application — do not reuse a
  password you use elsewhere.

The app formats amounts in Malawian kwacha (MWK). To change that, edit
`CURRENCY` and `LOCALE` at the top of `app.js`.
