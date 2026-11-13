/* ============================================================
   Personal Finance Tracker — app.js
   ------------------------------------------------------------
   A browser rebuild of the Python/Tkinter + SQLite app. There is
   no server: accounts and transactions live in localStorage, so
   the page works when opened directly or through Live Server.

   1.  Configuration
   2.  Storage
   3.  Authentication (Web Crypto PBKDF2, with a safe fallback)
   4.  Transactions
   5.  Formatting + validation helpers
   6.  Rendering
   7.  Dialog + events
   8.  Demo data
   9.  Start-up
   ============================================================ */

(() => {
  "use strict";


  /* ---------- 1. Configuration ------------------------------ */
  const STORAGE_KEY = "finance-tracker:v1";
  const CURRENCY = "MWK";
  const LOCALE = "en-US";
  const PBKDF2_ITERATIONS = 150000;

  const DEMO_USERNAME = "demo";
  const DEMO_PASSWORD = "demo1234";

  const INCOME_CATEGORIES = [
    "Salary", "Freelance", "Gift", "Refund", "Other income"
  ];

  const EXPENSE_CATEGORIES = [
    "Groceries", "Rent", "Transport", "Utilities", "Dining out",
    "Health", "Shopping", "Entertainment", "Other expense"
  ];

  const CHART_COLORS = [
    "#38bdf8", "#a78bfa", "#34d399", "#fbbf24",
    "#f472b6", "#60a5fa", "#fb7185"
  ];

  const money = new Intl.NumberFormat(LOCALE, {
    style: "currency",
    currency: CURRENCY
  });

  const currencySymbol = (() => {
    const part = money.formatToParts(0).find((item) => item.type === "currency");
    return part ? part.value : "MWK";
  })();

  let data = loadData();
  let currentUser = null;
  let authMode = "signin";
  let editingId = null;
  let toastTimer = null;

  // Filters are kept in one object so "Reset" has a single job.
  const filters = { search: "", type: "all", category: "all", month: "" };

  // Filled in once by cacheElements().
  const els = {};


  /* ---------- 2. Storage ------------------------------------ */
  function emptyData() {
    return { version: 1, users: [], transactions: [], sessionUserId: null };
  }

  function loadData() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return emptyData();

      const parsed = JSON.parse(raw);
      if (!parsed || !Array.isArray(parsed.users) || !Array.isArray(parsed.transactions)) {
        return emptyData();
      }

      return { ...emptyData(), ...parsed };
    } catch (error) {
      console.warn("Could not read saved finance data:", error);
      return emptyData();
    }
  }

  function saveData() {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
    } catch (error) {
      console.warn("Could not save finance data:", error);
      toast("Could not save — browser storage is full or blocked.");
    }
  }

  function newId() {
    if (window.crypto && typeof window.crypto.randomUUID === "function") {
      return window.crypto.randomUUID();
    }
    return `id-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  }

  function findUserByName(username) {
    const needle = String(username || "").trim().toLowerCase();
    return data.users.find((user) => user.username.toLowerCase() === needle) || null;
  }

  function userById(id) {
    return data.users.find((user) => user.id === id) || null;
  }

  function setSession(user) {
    currentUser = user;
    data.sessionUserId = user ? user.id : null;
    saveData();
  }


  /* ---------- 3. Authentication ----------------------------- */
  function preferredAlgorithm() {
    return window.crypto && window.crypto.subtle ? "pbkdf2" : "fnv1a";
  }

  function randomSalt() {
    const bytes = new Uint8Array(16);

    if (window.crypto && window.crypto.getRandomValues) {
      window.crypto.getRandomValues(bytes);
    } else {
      // Extremely old browsers: still better than a fixed salt.
      for (let i = 0; i < bytes.length; i += 1) {
        bytes[i] = Math.floor(Math.random() * 256);
      }
    }

    return bufferToBase64(bytes);
  }

  function bufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.length; i += 1) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  function base64ToBytes(value) {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  // Very small non-cryptographic hash, used only when Web Crypto is
  // unavailable. It keeps the demo working on old browsers, but it
  // is NOT secure — the login screen says so.
  function fnv1a(text) {
    let hash = 0x811c9dc5;
    for (let i = 0; i < text.length; i += 1) {
      hash ^= text.charCodeAt(i);
      hash = Math.imul(hash, 0x01000193);
    }
    return (hash >>> 0).toString(16).padStart(8, "0");
  }

  function fallbackHash(password, salt) {
    let digest = `${password}|${salt}`;
    for (let i = 0; i < 25000; i += 1) {
      digest = fnv1a(`${digest}|${i}`);
    }
    return digest;
  }

  async function hashPassword(password, salt, algorithm) {
    if (algorithm === "pbkdf2") {
      try {
        const keyMaterial = await window.crypto.subtle.importKey(
          "raw",
          new TextEncoder().encode(password),
          "PBKDF2",
          false,
          ["deriveBits"]
        );

        const bits = await window.crypto.subtle.deriveBits(
          {
            name: "PBKDF2",
            salt: base64ToBytes(salt),
            iterations: PBKDF2_ITERATIONS,
            hash: "SHA-256"
          },
          keyMaterial,
          256
        );

        return bufferToBase64(bits);
      } catch (error) {
        throw new Error(
          "This browser blocked password hashing. Try serving the page from a local web server."
        );
      }
    }

    return fallbackHash(password, salt);
  }

  async function createUser(username, password) {
    const name = String(username || "").trim();

    if (!/^[A-Za-z0-9_.-]{3,24}$/.test(name)) {
      throw new Error("Usernames need 3–24 characters: letters, numbers, dot, dash or underscore.");
    }
    if (String(password).length < 8) {
      throw new Error("Passwords must be at least 8 characters.");
    }
    if (findUserByName(name)) {
      throw new Error("That username is already taken.");
    }

    const algorithm = preferredAlgorithm();
    const salt = randomSalt();
    const hash = await hashPassword(password, salt, algorithm);

    const user = {
      id: newId(),
      username: name,
      salt,
      hash,
      algorithm,
      createdAt: new Date().toISOString()
    };

    data.users.push(user);
    saveData();
    return user;
  }

  async function verifyUser(username, password) {
    const user = findUserByName(username);
    if (!user) return null;

    const hash = await hashPassword(password, user.salt, user.algorithm);
    return hash === user.hash ? user : null;
  }


  /* ---------- 4. Transactions ------------------------------- */
  function userTransactions() {
    if (!currentUser) return [];
    return data.transactions.filter((tx) => tx.userId === currentUser.id);
  }

  function filteredTransactions() {
    const query = filters.search.trim().toLowerCase();

    return userTransactions()
      .filter((tx) => filters.type === "all" || tx.type === filters.type)
      .filter((tx) => filters.category === "all" || tx.category === filters.category)
      .filter((tx) => !filters.month || tx.date.startsWith(filters.month))
      .filter((tx) => {
        if (!query) return true;
        return tx.category.toLowerCase().includes(query)
          || String(tx.note || "").toLowerCase().includes(query);
      })
      .sort((a, b) => {
        // Newest first; createdAt breaks ties on the same day.
        return b.date.localeCompare(a.date)
          || String(b.createdAt).localeCompare(String(a.createdAt));
      });
  }

  function saveTransaction(values) {
    const now = new Date().toISOString();

    if (editingId) {
      const existing = data.transactions.find(
        (tx) => tx.id === editingId && tx.userId === currentUser.id
      );
      if (existing) Object.assign(existing, values, { updatedAt: now });
    } else {
      data.transactions.push({
        id: newId(),
        userId: currentUser.id,
        createdAt: now,
        ...values
      });
    }

    saveData();
  }

  function deleteTransaction(id) {
    const before = data.transactions.length;

    data.transactions = data.transactions.filter(
      (tx) => !(tx.id === id && tx.userId === currentUser.id)
    );

    if (data.transactions.length !== before) saveData();
  }


  /* ---------- 5. Formatting + validation helpers ------------ */
  function pad(value) {
    return String(value).padStart(2, "0");
  }

  function todayISO() {
    const today = new Date();
    return `${today.getFullYear()}-${pad(today.getMonth() + 1)}-${pad(today.getDate())}`;
  }

  function currentMonthKey() {
    return todayISO().slice(0, 7);
  }

  function parseISODate(value) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return null;

    const [year, month, day] = value.split("-").map(Number);
    const date = new Date(year, month - 1, day);

    if (
      date.getFullYear() !== year
      || date.getMonth() !== month - 1
      || date.getDate() !== day
    ) {
      return null;
    }

    return date;
  }

  function formatDate(value) {
    const date = parseISODate(value);
    if (!date) return value;
    return date.toLocaleDateString(LOCALE, {
      day: "2-digit",
      month: "short",
      year: "numeric"
    });
  }

  function formatMonth(key) {
    const date = parseISODate(`${key}-01`);
    if (!date) return key;
    return date.toLocaleDateString(LOCALE, { month: "long", year: "numeric" });
  }

  function formatMoney(cents) {
    return money.format(cents / 100);
  }

  function sumCents(list) {
    return list.reduce((total, tx) => total + tx.amountCents, 0);
  }

  function parseAmountInput(raw) {
    // Keep digits and the decimal point only, so pasted values such
    // as "MWK 45,000.00" or "45,000" are accepted.
    const cleaned = String(raw || "").replace(/[^0-9.]/g, "");
    if (!cleaned) return NaN;

    const value = Number(cleaned);
    if (!Number.isFinite(value)) return NaN;

    return Math.round(value * 100);
  }

  function validateTransaction(type, category, amountCents, date) {
    if (type !== "income" && type !== "expense") {
      return "Choose income or expense.";
    }
    if (!category) {
      return "Enter a category.";
    }
    if (category.length > 40) {
      return "Keep category names under 40 characters.";
    }
    if (!Number.isFinite(amountCents) || amountCents <= 0) {
      return "Enter an amount greater than zero.";
    }
    if (amountCents > 100000000000) {
      return "That amount is too large for this tracker.";
    }
    if (!parseISODate(date)) {
      return "Choose a valid date.";
    }
    return "";
  }


  /* ---------- 6. Rendering ---------------------------------- */
  function cacheElements() {
    els.authView = document.getElementById("auth-view");
    els.appView = document.getElementById("app-view");
    els.authForm = document.getElementById("auth-form");
    els.authUsername = document.getElementById("auth-username");
    els.authPassword = document.getElementById("auth-password");
    els.authHint = document.getElementById("auth-hint");
    els.authError = document.getElementById("auth-error");
    els.authSubmit = document.getElementById("auth-submit");
    els.authSwitchButtons = document.querySelectorAll(".auth-switch-btn");
    els.demoButton = document.getElementById("demo-btn");

    els.userName = document.getElementById("user-name");
    els.appSubtitle = document.getElementById("app-subtitle");
    els.addButton = document.getElementById("add-btn");
    els.logoutButton = document.getElementById("logout-btn");

    els.statBalance = document.getElementById("stat-balance");
    els.statBalanceNote = document.getElementById("stat-balance-note");
    els.statIncome = document.getElementById("stat-income");
    els.statIncomeNote = document.getElementById("stat-income-note");
    els.statExpense = document.getElementById("stat-expense");
    els.statExpenseNote = document.getElementById("stat-expense-note");

    els.chart = document.getElementById("chart");
    els.chartSub = document.getElementById("chart-sub");
    els.chartEmpty = document.getElementById("chart-empty");

    els.searchInput = document.getElementById("filter-search");
    els.typeFilter = document.getElementById("filter-type");
    els.categoryFilter = document.getElementById("filter-category");
    els.monthFilter = document.getElementById("filter-month");
    els.resetFilters = document.getElementById("filter-reset");

    els.txBody = document.getElementById("tx-body");
    els.txEmpty = document.getElementById("tx-empty");
    els.txSummary = document.getElementById("tx-summary");
    els.txCount = document.getElementById("tx-count");
    els.txIncome = document.getElementById("tx-income");
    els.txExpense = document.getElementById("tx-expense");
    els.txNet = document.getElementById("tx-net");

    els.dialog = document.getElementById("tx-dialog");
    els.dialogTitle = document.getElementById("tx-dialog-title");
    els.dialogForm = document.getElementById("tx-form");
    els.typeSelect = document.getElementById("tx-type");
    els.categoryInput = document.getElementById("tx-category");
    els.categoryList = document.getElementById("tx-category-options");
    els.amountInput = document.getElementById("tx-amount");
    els.amountPrefix = document.getElementById("amount-prefix");
    els.dateInput = document.getElementById("tx-date");
    els.noteInput = document.getElementById("tx-note");
    els.dialogError = document.getElementById("tx-error");
    els.cancelButton = document.getElementById("tx-cancel");
    els.saveButton = document.getElementById("tx-save");

    els.toast = document.getElementById("toast");
  }

  function renderAll() {
    if (!currentUser) return;

    const total = userTransactions().length;

    els.userName.textContent = currentUser.username;
    els.appSubtitle.textContent = total
      ? `${total} transaction${total === 1 ? "" : "s"} saved in this browser.`
      : "No transactions yet — add your first one above.";

    renderStats();
    renderChart();
    renderCategoryFilter();
    renderTable();
  }

  function renderStats() {
    const transactions = userTransactions();

    const totalIncome = sumCents(transactions.filter((tx) => tx.type === "income"));
    const totalExpense = sumCents(transactions.filter((tx) => tx.type === "expense"));
    const balance = totalIncome - totalExpense;

    els.statBalance.textContent = formatMoney(balance);
    els.statBalance.classList.toggle("is-negative", balance < 0);
    els.statBalanceNote.textContent = transactions.length
      ? `Across ${transactions.length} transaction${transactions.length === 1 ? "" : "s"}`
      : "No transactions yet";

    const month = currentMonthKey();
    const monthTransactions = transactions.filter((tx) => tx.date.startsWith(month));
    const monthExpenses = monthTransactions.filter((tx) => tx.type === "expense");

    els.statIncome.textContent = formatMoney(
      sumCents(monthTransactions.filter((tx) => tx.type === "income"))
    );
    els.statIncomeNote.textContent = formatMonth(month);

    els.statExpense.textContent = formatMoney(sumCents(monthExpenses));
    els.statExpenseNote.textContent = monthExpenses.length
      ? `${monthExpenses.length} expense${monthExpenses.length === 1 ? "" : "s"} in ${formatMonth(month)}`
      : `No expenses in ${formatMonth(month)}`;
  }

  function renderChart() {
    const month = currentMonthKey();
    const expenses = userTransactions().filter(
      (tx) => tx.type === "expense" && tx.date.startsWith(month)
    );

    els.chartSub.textContent = formatMonth(month);
    els.chart.replaceChildren();

    const hasData = expenses.length > 0;
    els.chartEmpty.hidden = hasData;
    els.chart.hidden = !hasData;

    if (!hasData) return;

    // Group the cents spent per category.
    const totals = new Map();
    for (const tx of expenses) {
      totals.set(tx.category, (totals.get(tx.category) || 0) + tx.amountCents);
    }

    let entries = [...totals.entries()].sort((a, b) => b[1] - a[1]);

    // Keep the chart readable: show the biggest categories plus "Other".
    if (entries.length > CHART_COLORS.length) {
      const rest = entries
        .slice(CHART_COLORS.length - 1)
        .reduce((total, entry) => total + entry[1], 0);
      entries = entries
        .slice(0, CHART_COLORS.length - 1)
        .concat([["Other categories", rest]]);
    }

    const monthTotal = sumCents(expenses);
    const biggest = entries[0][1] || 1;

    entries.forEach(([category, cents], index) => {
      const row = document.createElement("div");
      row.className = "chart-row";

      const head = document.createElement("div");
      head.className = "chart-head";

      const label = document.createElement("span");
      label.className = "chart-label";
      label.textContent = category;

      const amount = document.createElement("span");
      amount.className = "chart-amount";
      const percent = monthTotal ? Math.round((cents / monthTotal) * 100) : 0;
      amount.textContent = `${formatMoney(cents)} · ${percent}%`;

      head.append(label, amount);

      const track = document.createElement("div");
      track.className = "chart-track";

      const fill = document.createElement("div");
      fill.className = "chart-fill";
      fill.style.width = `${Math.max(2, (cents / biggest) * 100)}%`;
      fill.style.setProperty("--bar", CHART_COLORS[index % CHART_COLORS.length]);

      track.append(fill);
      row.append(head, track);
      els.chart.append(row);
    });
  }

  function renderCategoryFilter() {
    const categories = [...new Set(
      userTransactions().map((tx) => tx.category)
    )].sort((a, b) => a.localeCompare(b));

    if (filters.category !== "all" && !categories.includes(filters.category)) {
      filters.category = "all";
    }

    els.categoryFilter.replaceChildren();

    const allOption = document.createElement("option");
    allOption.value = "all";
    allOption.textContent = "All categories";
    els.categoryFilter.append(allOption);

    for (const category of categories) {
      const option = document.createElement("option");
      option.value = category;
      option.textContent = category;
      els.categoryFilter.append(option);
    }

    els.categoryFilter.value = filters.category;
  }

  function renderTable() {
    const transactions = filteredTransactions();

    els.txBody.replaceChildren();
    for (const tx of transactions) {
      els.txBody.append(buildRow(tx));
    }

    els.txEmpty.hidden = transactions.length > 0;
    els.txSummary.hidden = transactions.length === 0;

    const income = sumCents(transactions.filter((tx) => tx.type === "income"));
    const expense = sumCents(transactions.filter((tx) => tx.type === "expense"));
    const net = income - expense;

    els.txCount.textContent = `${transactions.length} transaction${transactions.length === 1 ? "" : "s"} shown`;
    els.txIncome.textContent = formatMoney(income);
    els.txExpense.textContent = formatMoney(expense);
    els.txNet.textContent = formatMoney(net);
    els.txNet.classList.toggle("amount-negative", net < 0);
  }

  function buildRow(tx) {
    const row = document.createElement("tr");

    const dateCell = document.createElement("td");
    const time = document.createElement("time");
    time.dateTime = tx.date;
    time.textContent = formatDate(tx.date);
    dateCell.append(time);

    const typeCell = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = `badge badge-${tx.type}`;
    badge.textContent = tx.type === "income" ? "Income" : "Expense";
    typeCell.append(badge);

    const categoryCell = document.createElement("td");
    categoryCell.textContent = tx.category;

    const noteCell = document.createElement("td");
    noteCell.className = "tx-note";
    noteCell.textContent = tx.note || "—";
    if (tx.note) noteCell.title = tx.note;

    const amountCell = document.createElement("td");
    amountCell.className = `amount ${tx.type === "income" ? "amount-income" : "amount-expense"}`;
    amountCell.textContent = `${tx.type === "income" ? "+" : "−"}${formatMoney(tx.amountCents)}`;

    const actionsCell = document.createElement("td");
    actionsCell.className = "actions-cell";

    const actions = document.createElement("div");
    actions.className = "row-actions";

    const editButton = document.createElement("button");
    editButton.type = "button";
    editButton.className = "row-btn";
    editButton.textContent = "Edit";
    editButton.setAttribute(
      "aria-label",
      `Edit ${tx.category} entry from ${formatDate(tx.date)}`
    );
    editButton.addEventListener("click", () => openDialog(tx));

    const deleteButton = document.createElement("button");
    deleteButton.type = "button";
    deleteButton.className = "row-btn danger";
    deleteButton.textContent = "Delete";
    deleteButton.setAttribute(
      "aria-label",
      `Delete ${tx.category} entry from ${formatDate(tx.date)}`
    );
    deleteButton.addEventListener("click", () => {
      const confirmed = window.confirm(
        `Delete this ${tx.category} entry from ${formatDate(tx.date)}? This cannot be undone.`
      );
      if (!confirmed) return;

      deleteTransaction(tx.id);
      renderAll();
      toast("Transaction deleted.");
    });

    actions.append(editButton, deleteButton);
    actionsCell.append(actions);

    row.append(dateCell, typeCell, categoryCell, noteCell, amountCell, actionsCell);
    return row;
  }

  function showView(loggedIn) {
    els.authView.hidden = loggedIn;
    els.appView.hidden = !loggedIn;

    if (loggedIn) renderAll();
  }


  /* ---------- 7. Dialog + events ---------------------------- */
  function toast(message) {
    els.toast.textContent = message;
    els.toast.classList.add("is-visible");

    window.clearTimeout(toastTimer);
    toastTimer = window.setTimeout(() => {
      els.toast.classList.remove("is-visible");
    }, 4000);
  }

  function showAuthError(message) {
    els.authError.textContent = message;
    els.authError.hidden = false;
  }

  function setAuthMode(mode) {
    authMode = mode;

    els.authSwitchButtons.forEach((button) => {
      button.setAttribute("aria-pressed", String(button.dataset.mode === mode));
    });

    const registering = mode === "register";
    els.authSubmit.textContent = registering ? "Create account" : "Sign in";
    els.authPassword.setAttribute(
      "autocomplete",
      registering ? "new-password" : "current-password"
    );
    els.authHint.hidden = !registering;
    els.authError.hidden = true;
  }

  function setAuthBusy(busy) {
    els.authSubmit.disabled = busy;
    els.demoButton.disabled = busy;
    els.authSwitchButtons.forEach((button) => {
      button.disabled = busy;
    });

    if (busy) {
      els.authSubmit.textContent = authMode === "register"
        ? "Creating account…"
        : "Signing in…";
    } else {
      els.authSubmit.textContent = authMode === "register"
        ? "Create account"
        : "Sign in";
    }
  }

  async function handleAuthSubmit(event) {
    event.preventDefault();

    const username = els.authUsername.value.trim();
    const password = els.authPassword.value;

    els.authError.hidden = true;

    if (!username || !password) {
      showAuthError("Enter a username and password.");
      return;
    }

    setAuthBusy(true);

    try {
      if (authMode === "register") {
        const user = await createUser(username, password);
        setSession(user);
        toast(`Welcome, ${user.username}! Your account is ready.`);
      } else {
        const user = await verifyUser(username, password);
        if (!user) throw new Error("Username or password is incorrect.");
        setSession(user);
        toast(`Welcome back, ${user.username}.`);
      }

      els.authForm.reset();
      resetFilters(false);
      showView(true);
    } catch (error) {
      showAuthError(error.message || "Something went wrong. Please try again.");
    } finally {
      setAuthBusy(false);
    }
  }

  async function handleDemoClick() {
    const originalLabel = els.demoButton.textContent;

    els.demoButton.disabled = true;
    els.demoButton.textContent = "Preparing demo…";

    try {
      let user = findUserByName(DEMO_USERNAME);

      if (!user) {
        user = await createUser(DEMO_USERNAME, DEMO_PASSWORD);
      }

      if (!user.seeded) {
        seedDemoTransactions(user.id);
        user.seeded = true;
        saveData();
      }

      setSession(user);
      resetFilters(false);
      showView(true);
      toast("Signed in to the demo account — sample data included.");
    } catch (error) {
      showAuthError(error.message || "Could not open the demo account.");
    } finally {
      els.demoButton.disabled = false;
      els.demoButton.textContent = originalLabel;
    }
  }

  function handleLogout() {
    setSession(null);
    els.authForm.reset();
    setAuthMode("signin");
    resetFilters(false);
    showView(false);
    els.authUsername.focus();
  }

  function updateCategorySuggestions() {
    const categories = els.typeSelect.value === "income"
      ? INCOME_CATEGORIES
      : EXPENSE_CATEGORIES;

    els.categoryList.replaceChildren();

    for (const category of categories) {
      const option = document.createElement("option");
      option.value = category;
      els.categoryList.append(option);
    }
  }

  function setDialogError(message) {
    els.dialogError.textContent = message;
    els.dialogError.hidden = !message;
  }

  function openDialog(tx = null) {
    editingId = tx ? tx.id : null;

    els.dialogTitle.textContent = tx ? "Edit transaction" : "Add transaction";
    els.saveButton.textContent = tx ? "Save changes" : "Add transaction";
    els.dialogForm.reset();
    setDialogError("");

    if (tx) {
      els.typeSelect.value = tx.type;
      els.categoryInput.value = tx.category;
      els.amountInput.value = (tx.amountCents / 100).toFixed(2);
      els.dateInput.value = tx.date;
      els.noteInput.value = tx.note || "";
    } else {
      els.typeSelect.value = "expense";
      els.dateInput.value = todayISO();
    }

    updateCategorySuggestions();
    els.dialog.showModal();

    if (tx) {
      els.amountInput.focus();
    } else {
      els.categoryInput.focus();
    }
  }

  function handleTransactionSubmit(event) {
    event.preventDefault();

    const type = els.typeSelect.value;
    const category = els.categoryInput.value.trim();
    const amountCents = parseAmountInput(els.amountInput.value);
    const date = els.dateInput.value;
    const note = els.noteInput.value.trim();
    const problem = validateTransaction(type, category, amountCents, date);

    if (problem) {
      setDialogError(problem);
      return;
    }

    const wasEditing = editingId !== null;

    saveTransaction({ type, category, amountCents, date, note });
    editingId = null;
    els.dialog.close();

    // A brand-new entry might not match the current filters, which
    // would make it look like nothing happened. Start from a clean view.
    if (!wasEditing) resetFilters(false);

    renderAll();
    toast(wasEditing ? "Transaction updated." : "Transaction added.");
  }

  function resetFilters(render = true) {
    filters.search = "";
    filters.type = "all";
    filters.category = "all";
    filters.month = "";

    els.searchInput.value = "";
    els.typeFilter.value = "all";
    els.monthFilter.value = "";

    if (els.categoryFilter.options.length) {
      els.categoryFilter.value = "all";
    }

    if (render) renderTable();
  }

  function bindEvents() {
    els.authSwitchButtons.forEach((button) => {
      button.addEventListener("click", () => setAuthMode(button.dataset.mode));
    });

    els.authForm.addEventListener("submit", handleAuthSubmit);
    els.demoButton.addEventListener("click", handleDemoClick);
    els.logoutButton.addEventListener("click", handleLogout);
    els.addButton.addEventListener("click", () => openDialog(null));

    els.dialogForm.addEventListener("submit", handleTransactionSubmit);
    els.cancelButton.addEventListener("click", () => els.dialog.close());
    els.dialog.addEventListener("close", () => {
      editingId = null;
    });
    els.typeSelect.addEventListener("change", updateCategorySuggestions);

    els.searchInput.addEventListener("input", () => {
      filters.search = els.searchInput.value;
      renderTable();
    });

    els.typeFilter.addEventListener("change", () => {
      filters.type = els.typeFilter.value;
      renderTable();
    });

    els.categoryFilter.addEventListener("change", () => {
      filters.category = els.categoryFilter.value;
      renderTable();
    });

    els.monthFilter.addEventListener("change", () => {
      const value = els.monthFilter.value;
      // Some browsers do not support type="month" and fall back to
      // a text box, so only accept a real YYYY-MM value.
      filters.month = /^\d{4}-(0[1-9]|1[0-2])$/.test(value) ? value : "";
      renderTable();
    });

    els.resetFilters.addEventListener("click", () => resetFilters());
  }


  /* ---------- 8. Demo data ---------------------------------- */
  function seedDemoTransactions(userId) {
    const now = new Date();

    for (let back = 0; back < 3; back += 1) {
      const month = new Date(now.getFullYear(), now.getMonth() - back, 1);
      const daysInMonth = new Date(month.getFullYear(), month.getMonth() + 1, 0).getDate();
      const lastDay = back === 0 ? now.getDate() : daysInMonth;

      // Spread the sample entries across the part of the month that
      // has already happened, so the current month is never empty.
      const dayAt = (fraction) => Math.min(
        lastDay,
        Math.max(1, Math.round(daysInMonth * fraction))
      );

      const iso = (fraction) => (
        `${month.getFullYear()}-${pad(month.getMonth() + 1)}-${pad(dayAt(fraction))}`
      );

      const entries = [
        ["income", "Salary", 1250000, 0.02, "Monthly salary"],
        ["income", "Freelance", 280000 + back * 25000, 0.40, "Client website"],
        ["expense", "Rent", 320000, 0.05, "Apartment rent"],
        ["expense", "Groceries", 85000, 0.20, "Weekly shop"],
        ["expense", "Groceries", 52000, 0.55, "Weekly shop"],
        ["expense", "Transport", 30000, 0.30, "Bus pass"],
        ["expense", "Utilities", 45000 + back * 2500, 0.35, "Electricity and water"],
        ["expense", "Dining out", 28000, 0.65, "Dinner with friends"],
        ["expense", "Entertainment", 9500, 0.75, "Streaming subscription"],
        ["expense", "Shopping", 42000, 0.85, "New shoes"],
        ["expense", "Health", 18000, 0.90, "Pharmacy"]
      ];

      for (const [type, category, amount, fraction, note] of entries) {
        data.transactions.push({
          id: newId(),
          userId,
          type,
          category,
          amountCents: Math.round(amount * 100),
          date: iso(fraction),
          note,
          createdAt: new Date(
            month.getTime() + fraction * 24 * 60 * 60 * 1000
          ).toISOString()
        });
      }
    }
  }


  /* ---------- 9. Start-up ----------------------------------- */
  function init() {
    cacheElements();
    bindEvents();

    els.amountPrefix.textContent = currencySymbol;

    const savedUser = data.sessionUserId ? userById(data.sessionUserId) : null;

    if (savedUser) {
      currentUser = savedUser;
      showView(true);
    } else {
      showView(false);
    }
  }

  init();
})();
