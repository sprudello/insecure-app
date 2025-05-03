var userKey = 'loggedInUser';

function onLogin() {
    var inputUsername = document.getElementById("username");
    var inputPassword = document.getElementById("password");

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
            }
            else {
                throw new Error(response.statusText + " (" + response.status + ")");
            }
        })
        .then((data) => {
            // Store JWT token
            saveUser(data);
            window.location.href = "index.html";
        })
        .catch((error) => {
            var labelResult = document.getElementById("labelResult");
            labelResult.innerText = error;
            labelResult.classList.remove("hidden");
        });
}


function toggleDropdown() {
    var dropdownContent = document.getElementById("dropdownContent");
    dropdownContent.style.display = dropdownContent.style.display === "block" ? "none" : "block";
}

function logout() {
    var dropdownContent = document.getElementById("dropdownContent");
    dropdownContent.style.display = dropdownContent.style.display === "block" ? "none" : "block";
    resetUser();
    window.location.href = "index.html";
}

function saveUser(user) {
    localStorage.setItem(userKey, JSON.stringify(user));
}

function getUsername() {
    var userString = localStorage.getItem(userKey);
    var userObject = JSON.parse(userString);
    return userObject.username;
}

function getUserid() {
    var userString = localStorage.getItem(userKey);
    var userObject = JSON.parse(userString);
    return userObject.id;
}

function resetUser() {
    localStorage.removeItem(userKey);
}

function isAdmin() {
    var userString = localStorage.getItem(userKey);
    var userObject = JSON.parse(userString);
    return userObject.isAdmin;
}

function isLoggedIn() {
    var userString = localStorage.getItem(userKey);
    return userString != null;
}

function createLoginForm() {
    /* Title. */
    var mainTitle = document.createElement("h1");
    mainTitle.innerText = "Login";

    var main = document.getElementById("main");
    main.appendChild(mainTitle);

    /* Username. */
    var labelUsername = document.createElement("label");
    labelUsername.innerText = "Username";

    var inputUsername = document.createElement("input");
    inputUsername.id = "username";

    var divUsername = document.createElement("div");
    divUsername.appendChild(labelUsername);
    divUsername.innerHTML += '<br>';
    divUsername.appendChild(inputUsername);

    /* Password. */
    var labelPassword = document.createElement("label");
    labelPassword.innerText = "Password";

    var inputPassword = document.createElement("input");
    inputPassword.id = "password";
    inputPassword.type = "password";

    var divPassword = document.createElement("div");
    divPassword.innerHTML += '<br>';
    divPassword.appendChild(labelPassword);
    divPassword.innerHTML += '<br>';
    divPassword.appendChild(inputPassword);

    /* Result label */
    var labelResult = document.createElement("label");
    labelResult.innerText = "Login result";
    labelResult.id = "labelResult";
    labelResult.classList.add("warning");
    labelResult.classList.add("hidden");

    var divResult = document.createElement("div");
    divResult.appendChild(labelResult);

    /* Login button. */
    var submitButton = document.createElement("input");
    submitButton.type = "submit";
    submitButton.value = "Login";

    var divButton = document.createElement("div");
    divButton.appendChild(submitButton);

    /* Login form. */
    var loginForm = document.createElement("form");
    loginForm.action = "javascript:onLogin()";
    loginForm.appendChild(divUsername);
    loginForm.appendChild(divPassword);
    loginForm.appendChild(divResult);
    loginForm.appendChild(divButton);

    main.appendChild(loginForm);
}
