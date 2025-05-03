var userKey = 'loggedInUser';

// Add a global variable to store user ID during 2FA step
let pendingUserId = null;

function onLogin() {
    var inputUsername = document.getElementById("username");
    var inputPassword = document.getElementById("password");
    var labelResult = document.getElementById("labelResult");
    if (labelResult) labelResult.classList.add("hidden"); // Hide previous errors

    fetch("/api/Login", {
        method: "POST",
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ Username: inputUsername.value, Password: inputPassword.value })
    })
    .then((response) => {
        if (response.ok) {
            return response.json();
        } else {
            return response.text().then(text => {
                throw new Error(text || (response.statusText + " (" + response.status + ")"));
            });
        }
    })
    .then((data) => {
        if (data.requiresTwoFactor) {
            // Store user ID and show 2FA input
            pendingUserId = data.userId; // Make sure backend sends userId when 2FA is required
            showTwoFactorInput();
        } else {
            // Login successful, store token and redirect
            saveUser(data); // saveUser should store the whole object including token
            window.location.href = "index.html"; // Redirect to home page
        }
    })
    .catch((error) => {
        if (labelResult) {
            labelResult.innerText = "Login failed: " + error.message;
            labelResult.classList.remove("hidden");
        }
        toastr.error("Login failed: " + error.message, 'Error');
    });
}

function showTwoFactorInput() {
    const divUsername = document.getElementById("divUsername");
    const divPassword = document.getElementById("divPassword");
    const divTwoFactor = document.getElementById("divTwoFactor");
    const loginButton = document.getElementById("loginButton");
    const loginForm = document.getElementById("loginForm");
    const tfaCodeInput = document.getElementById("tfa-code");

    if (divUsername) divUsername.style.display = 'none';
    if (divPassword) divPassword.style.display = 'none';
    if (divTwoFactor) divTwoFactor.style.display = 'block'; // Show 2FA div
    if (loginButton) loginButton.value = 'Verify Code'; // Change button text
    // Change form submit handler
    if (loginForm) loginForm.onsubmit = function() { onVerify2FA(); return false; };
    if (tfaCodeInput) tfaCodeInput.focus(); // Focus the 2FA input
}

function onVerify2FA() {
    var inputCode = document.getElementById("tfa-code");
    var labelResult = document.getElementById("labelResult");
    if (labelResult) labelResult.classList.add("hidden"); // Hide previous errors

    if (!pendingUserId || !inputCode || !inputCode.value) {
        if (labelResult) {
            labelResult.innerText = "Code is required.";
            labelResult.classList.remove("hidden");
        }
        toastr.warning("Code is required.", 'Warning');
        return;
    }

    fetch("/api/Login/verify-2fa", {
        method: "POST",
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ UserId: pendingUserId, Code: inputCode.value })
    })
    .then((response) => {
        if (response.ok) {
            return response.json();
        } else {
             return response.text().then(text => {
                throw new Error(text || (response.statusText + " (" + response.status + ")"));
            });
        }
    })
    .then((data) => {
        // 2FA successful, store token and redirect
        saveUser(data);
        window.location.href = "index.html"; // Redirect to home page
    })
    .catch((error) => {
        if (labelResult) {
            labelResult.innerText = "Verification failed: " + error.message;
            labelResult.classList.remove("hidden");
        }
        toastr.error("Verification failed: " + error.message, 'Error');
    });
}

// Function to reset the form back to username/password (optional)
function resetToPasswordLogin() {
    pendingUserId = null;
    const divUsername = document.getElementById("divUsername");
    const divPassword = document.getElementById("divPassword");
    const divTwoFactor = document.getElementById("divTwoFactor");
    const loginButton = document.getElementById("loginButton");
    const loginForm = document.getElementById("loginForm");
    const usernameInput = document.getElementById("username");

    if (divUsername) divUsername.style.display = 'block';
    if (divPassword) divPassword.style.display = 'block';
    if (divTwoFactor) divTwoFactor.style.display = 'none';
    if (loginButton) loginButton.value = 'Login';
    if (loginForm) loginForm.onsubmit = function() { onLogin(); return false; };
    if (usernameInput) usernameInput.focus();
}

// --- Existing helper functions ---
function toggleDropdown() {
    var dropdownContent = document.getElementById("dropdownContent");
    if (dropdownContent) {
        dropdownContent.style.display = dropdownContent.style.display === "block" ? "none" : "block";
    }
}

function logout() {
    resetUser(); // Clear user data from localStorage
    window.location.href = "index.html"; // Redirect to home page (which will show login prompt)
}

function saveUser(user) {
    // Ensure user object is valid before saving
    if (user && user.token) {
        localStorage.setItem(userKey, JSON.stringify(user));
    } else {
        console.error("Attempted to save invalid user data:", user);
        // Optionally clear storage if data is invalid
        // localStorage.removeItem(userKey);
    }
}

function getUserData() { // Renamed from previous example to avoid conflict if defined elsewhere
    const userString = localStorage.getItem(userKey);
    try {
        return userString ? JSON.parse(userString) : null;
    } catch (e) {
        console.error("Error parsing user data from localStorage", e);
        localStorage.removeItem(userKey); // Clear corrupted data
        return null;
    }
}


function getUsername() {
    var user = getUserData();
    return user ? user.username : null;
}

function getUserid() {
    var user = getUserData();
    return user ? user.id : null;
}

function resetUser() {
    localStorage.removeItem(userKey);
}

function isAdmin() {
    var user = getUserData();
    return user ? user.isAdmin : false;
}

function isLoggedIn() {
    // Check not just if item exists, but if it contains a token
    var user = getUserData();
    return !!user && !!user.token;
}

// --- Modified createLoginForm ---
function createLoginForm() {
    var main = document.getElementById("main");
    if (!main) return;
    main.innerHTML = ''; // Clear previous content

    var mainTitle = document.createElement("h1");
    mainTitle.innerText = "Login";
    main.appendChild(mainTitle);

    /* Username. */
    var labelUsername = document.createElement("label");
    labelUsername.innerText = "Username";
    var inputUsername = document.createElement("input");
    inputUsername.id = "username";
    inputUsername.autocomplete = "username"; // Help password managers
    var divUsername = document.createElement("div");
    divUsername.id = "divUsername";
    divUsername.appendChild(labelUsername);
    divUsername.innerHTML += '<br>';
    divUsername.appendChild(inputUsername);

    /* Password. */
    var labelPassword = document.createElement("label");
    labelPassword.innerText = "Password";
    var inputPassword = document.createElement("input");
    inputPassword.id = "password";
    inputPassword.type = "password";
    inputPassword.autocomplete = "current-password"; // Help password managers
    var divPassword = document.createElement("div");
    divPassword.id = "divPassword";
    divPassword.innerHTML += '<br>';
    divPassword.appendChild(labelPassword);
    divPassword.innerHTML += '<br>';
    divPassword.appendChild(inputPassword);

    /* 2FA Code Input (Initially Hidden) */
    var labelTwoFactor = document.createElement("label");
    labelTwoFactor.innerText = "Verification Code";
    var inputTwoFactor = document.createElement("input");
    inputTwoFactor.id = "tfa-code";
    inputTwoFactor.type = "text";
    inputTwoFactor.autocomplete = "off"; // Don't autocomplete 2FA codes
    inputTwoFactor.inputMode = "numeric";
    inputTwoFactor.pattern = "[0-9]{6}"; // Expect 6 digits
    inputTwoFactor.maxLength = 6;
    var divTwoFactor = document.createElement("div");
    divTwoFactor.id = "divTwoFactor";
    divTwoFactor.style.display = 'none'; // Hide initially
    divTwoFactor.innerHTML += '<br>';
    divTwoFactor.appendChild(labelTwoFactor);
    divTwoFactor.innerHTML += '<br>';
    divTwoFactor.appendChild(inputTwoFactor);

    /* Result label */
    var labelResult = document.createElement("label");
    labelResult.id = "labelResult";
    labelResult.classList.add("warning");
    labelResult.classList.add("hidden");
    var divResult = document.createElement("div");
    divResult.style.marginTop = '1em'; // Add some space
    divResult.appendChild(labelResult);

    /* Login button. */
    var submitButton = document.createElement("input");
    submitButton.type = "submit";
    submitButton.value = "Login";
    submitButton.id = "loginButton";
    var divButton = document.createElement("div");
    divButton.style.marginTop = '1em'; // Add some space
    divButton.appendChild(submitButton);

    /* Login form. */
    var loginForm = document.createElement("form");
    loginForm.id = "loginForm";
    // Set initial submit handler
    loginForm.onsubmit = function() { onLogin(); return false; }; // Prevent default form submission
    loginForm.appendChild(divUsername);
    loginForm.appendChild(divPassword);
    loginForm.appendChild(divTwoFactor); // Add the 2FA div
    loginForm.appendChild(divResult);
    loginForm.appendChild(divButton);

    main.appendChild(loginForm);
    inputUsername.focus(); // Focus username field initially
}