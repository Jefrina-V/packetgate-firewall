const AUTH_API = "http://127.0.0.1:5000/api/auth";

// If already logged in, skip straight to the dashboard.
if (localStorage.getItem("pg_token")) {
  window.location.href = "index.html";
}

function showAuthError(message) {
  const el = document.getElementById("authError");
  if (!el) return;
  el.textContent = message;
  el.classList.remove("hidden");
  const success = document.getElementById("authSuccess");
  if (success) success.classList.add("hidden");
}

function showAuthSuccess(message) {
  const el = document.getElementById("authSuccess");
  if (!el) return;
  el.textContent = message;
  el.classList.remove("hidden");
  const error = document.getElementById("authError");
  if (error) error.classList.add("hidden");
}

async function handleLogin(username, password) {
  try {
    const r = await fetch(`${AUTH_API}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password })
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || "Login failed.");

    localStorage.setItem("pg_token", data.token);
    localStorage.setItem("pg_username", data.username);
    window.location.href = "index.html";
  } catch (e) {
    showAuthError(e.message);
  }
}

async function handleSignup(username, password) {
  try {
    const r = await fetch(`${AUTH_API}/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password })
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || "Signup failed.");

    showAuthSuccess("Account created. Redirecting to log in...");
    setTimeout(() => (window.location.href = "login.html"), 1200);
  } catch (e) {
    showAuthError(e.message);
  }
}