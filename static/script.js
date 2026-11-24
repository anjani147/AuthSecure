
let accessToken = null;

const loginSection = document.getElementById("login-section");
const registerSection = document.getElementById("register-section");
const dashboardSection = document.getElementById("dashboard-section");
const message = document.getElementById("message");

function showSection(section) {
    loginSection.hidden = true;
    registerSection.hidden = true;
    dashboardSection.hidden = true;

    section.hidden = false;
    message.textContent = "";
}

function showMessage(text, success = false) {
    message.textContent = text;
    message.style.color = success ? "#4ade80" : "#f87171";
}

function getError(data) {
    return typeof data.detail === "string"
        ? data.detail
        : "Request failed. Check your input.";
}


// Switch between login and registration

document.getElementById("show-register")
    .addEventListener("click", (event) => {
        event.preventDefault();
        showSection(registerSection);
    });

document.getElementById("show-login")
    .addEventListener("click", (event) => {
        event.preventDefault();
        showSection(loginSection);
    });


// Registration

document.getElementById("register-form")
    .addEventListener("submit", async (event) => {

        event.preventDefault();

        const username =
            document.getElementById("register-username").value;

        const password =
            document.getElementById("register-password").value;

        try {
            const response = await fetch("/register", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();

            if (!response.ok) {
                showMessage(getError(data));
                return;
            }

            event.target.reset();
            showSection(loginSection);
            showMessage("Account created. Please sign in.", true);

        } catch (error) {
            showMessage("Registration request failed.");
            console.error(error);
        }
    });


// Login

document.getElementById("login-form")
    .addEventListener("submit", async (event) => {

        event.preventDefault();

        const username =
            document.getElementById("login-username").value;

        const password =
            document.getElementById("login-password").value;

        try {
            const response = await fetch("/login", {
                method: "POST",
                credentials: "same-origin",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();

            if (!response.ok) {
                showMessage(getError(data));
                return;
            }

            accessToken = data.access_token;

            event.target.reset();

            await loadDashboard();

        } catch (error) {
            showMessage("Login request failed.");
            console.error(error);
        }
    });


// Refresh access token

async function refreshAccessToken() {

    const response = await fetch("/refresh", {
        method: "POST",
        credentials: "same-origin"
    });

    if (!response.ok) {
        accessToken = null;
        return false;
    }

    const data = await response.json();

    accessToken = data.access_token;

    return true;
}


// Load protected dashboard

async function loadDashboard() {

    let response = await fetch("/dashboard", {
        headers: {
            "Authorization": `Bearer ${accessToken}`
        }
    });

    // Renew expired access token

    if (response.status === 401) {

        const refreshed = await refreshAccessToken();

        if (!refreshed) {
            showSection(loginSection);
            showMessage("Session expired. Please sign in.");
            return;
        }

        response = await fetch("/dashboard", {
            headers: {
                "Authorization": `Bearer ${accessToken}`
            }
        });
    }

    const data = await response.json();

    if (!response.ok) {
        accessToken = null;
        showSection(loginSection);
        showMessage(getError(data));
        return;
    }

    document.getElementById("display-username")
        .textContent = data.username;

    document.getElementById("display-id")
        .textContent = data.user_id;

    showSection(dashboardSection);
}


// Server-side logout

document.getElementById("logout-button")
    .addEventListener("click", async () => {

        try {
            const response = await fetch("/logout", {
                method: "POST",
                credentials: "same-origin"
            });

            if (!response.ok) {
                showMessage("Logout failed. Please try again.");
                return;
            }

            accessToken = null;

            document.getElementById("display-username")
                .textContent = "";

            document.getElementById("display-id")
                .textContent = "";

            showSection(loginSection);
            showMessage("Logged out successfully.", true);

        } catch (error) {
            showMessage("Logout failed. Please try again.");
            console.error(error);
        }
    });


// Restore session when website loads

async function restoreSession() {

    try {
        const refreshed = await refreshAccessToken();

        if (refreshed) {
            await loadDashboard();
        } else {
            showSection(loginSection);
        }

    } catch (error) {
        showSection(loginSection);
        console.error(error);
    }
}

restoreSession();
