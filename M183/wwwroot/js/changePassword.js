// --- Helper function to calculate Roman numeral value ---
const romanMap = { 'I': 1, 'V': 5, 'X': 10, 'L': 50, 'C': 100, 'D': 500, 'M': 1000 };

function calculateRomanValue(romanSequence) {
    let totalValue = 0;
    const length = romanSequence.length;
    for (let i = 0; i < length; i++) {
        const currentVal = romanMap[romanSequence[i]];
        if (currentVal === undefined) return 0;
        const nextVal = (i + 1 < length) ? romanMap[romanSequence[i + 1]] : undefined;
        if (nextVal !== undefined && nextVal > currentVal) {
            totalValue -= currentVal;
        } else {
            totalValue += currentVal;
        }
    }
    return totalValue;
}
// --- End Helper ---

// --- Password Rule Definitions ---
const passwordRules = [
    { id: 'rule-length', text: 'Minimum 8 characters long', validate: (pw) => pw.length >= 8 },
    { id: 'rule-uppercase', text: 'At least one uppercase letter (A-Z)', validate: (pw) => /[A-Z]/.test(pw) },
    { id: 'rule-number', text: 'At least one number (0-9)', validate: (pw) => /[0-9]/.test(pw) },
    { id: 'rule-special', text: 'At least one special character (e.g., !@#$%^&*)', validate: (pw) => /[!@#$%^&*()\-_=+[\]{}|;:'",.<>/?~]/.test(pw) },
    { id: 'rule-fruit', text: 'Must contain a fruit name (case-insensitive): apple, banana, orange, grape, or pear', validate: (pw) => ["apple", "banana", "orange", "grape", "pear"].some(fruit => pw.toLowerCase().includes(fruit)) },
    {
        id: 'rule-roman-count', text: 'Must contain at least two separate sequences of uppercase Roman numerals (I, V, X, L, C, D, M)', validate: (pw) => {
            const romanMatches = pw.match(/[IVXLCDM]+/g);
            return romanMatches ? romanMatches.length >= 2 : false;
        }
    },
    {
        id: 'rule-roman-sum', text: 'The total calculated value of all Roman numeral sequences must sum up to exactly 69', validate: (pw) => {
            const romanMatches = pw.match(/[IVXLCDM]+/g);
            if (!romanMatches || romanMatches.length < 2) return false; // Depends on previous rule
            let totalRomanValue = 0;
            romanMatches.forEach(match => {
                totalRomanValue += calculateRomanValue(match);
            });
            return totalRomanValue === 69;
        }
    }
];
// --- End Password Rule Definitions ---

// --- Function to Update Rule Display ---
function updatePasswordRulesDisplay() {
    const passwordInput = document.getElementById('password');
    const rulesList = document.getElementById('password-rules-list');
    if (!passwordInput || !rulesList) return;

    const newPassword = passwordInput.value;
    let allPreviousMet = true;

    passwordRules.forEach((rule, index) => {
        const ruleElement = document.getElementById(rule.id);
        if (!ruleElement) return;

        const currentRuleMet = allPreviousMet && rule.validate(newPassword);

        if (currentRuleMet) {
            ruleElement.style.display = 'list-item'; // Show rule
            ruleElement.style.color = 'green'; // Indicate success (optional)
        } else {
            // If this rule isn't met, hide it and all subsequent rules
            for (let j = index; j < passwordRules.length; j++) {
                const subsequentRuleElement = document.getElementById(passwordRules[j].id);
                if (subsequentRuleElement) {
                    subsequentRuleElement.style.display = 'none'; // Hide rule
                }
            }
            // Show the current rule (the one that failed) but indicate it's not met
            if (allPreviousMet) { // Only show the *first* unmet rule
                 ruleElement.style.display = 'list-item';
                 ruleElement.style.color = 'red'; // Indicate failure (optional)
            }

            allPreviousMet = false; // Mark that subsequent rules depend on this one
        }
    });
}
// --- End Function to Update Rule Display ---


function onPasswordChange() {
    var inputCurrentPassword = document.getElementById('currentPassword');
    var inputPassword = document.getElementById('password');
    var inputConfirmPassword = document.getElementById('confirmPassword');
    const newPassword = inputPassword.value;

    // --- Basic Input Checks ---
    if (!inputCurrentPassword.value) {
        toastr.warning('Current Password cannot be empty', 'Warning'); return;
    }
    if (!newPassword) {
        toastr.warning('New Password cannot be empty', 'Warning'); return;
    }
    if (newPassword != inputConfirmPassword.value) {
        toastr.warning('New passwords do not match', 'Warning'); return;
    }
    if (inputCurrentPassword.value === newPassword) {
        toastr.warning('New password cannot be the same as the current password.', 'Warning'); return;
    }

    // --- Final Password Rules Validation (Server will re-validate anyway) ---
    let validationError = null;
    let allRulesMet = true;
    for (const rule of passwordRules) {
        if (!rule.validate(newPassword)) {
            // Find the specific error message (more user-friendly than just stopping)
            const ruleElement = document.getElementById(rule.id);
            validationError = ruleElement ? ruleElement.textContent : "Password does not meet all requirements.";
            allRulesMet = false;
            break; // Stop on first failure
        }
    }

    if (!allRulesMet) {
        toastr.warning(validationError || "Password does not meet all requirements.", 'Password Rule Violation');
        return; // Stop if validation fails
    }
    // --- End Final Password Rules Validation ---


    const user = getUserData();
    if (!user || !user.token) {
        toastr.error('You must be logged in to change your password.', 'Error');
        return;
    }

    // --- Fetch call ---
    fetch('/api/User/password-update', {
        method: 'PATCH',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${user.token}`
        },
        body: JSON.stringify({
            UserId: user.id,
            CurrentPassword: inputCurrentPassword.value,
            NewPassword: newPassword,
        })
    })
        .then(async (response) => {
            if (response.ok) {
                toastr.success(
                    'Password changed successfully!',
                    'Success',
                    {
                        timeOut: 2000,
                        fadeOut: 1000,
                        onHidden: function () {
                            logout();
                        }
                    }
                );
            } else {
                const errorText = await response.text();
                toastr.error(`Password change failed: ${errorText || response.statusText}`, 'Error');
            }
        })
        .catch((error) => {
            console.error("Password change error:", error);
            toastr.error('An unexpected error occurred during password change.', 'Error');
        });
}

// --- Function to toggle password visibility ---
function togglePasswordVisibility() {
    const passwordInput = document.getElementById('password');
    const confirmPasswordInput = document.getElementById('confirmPassword');
    const showPasswordCheckbox = document.getElementById('showPassword');

    if (!passwordInput || !confirmPasswordInput || !showPasswordCheckbox) return;

    const type = showPasswordCheckbox.checked ? 'text' : 'password';
    passwordInput.type = type;
    confirmPasswordInput.type = type;
}
// --- End Function to toggle password visibility ---

function createChangePasswordForm() {
    /* Title. */
    var mainTitle = document.createElement('h1');
    mainTitle.innerText = 'Change password';

    var main = document.getElementById('main');
    if (!main) return;
    main.innerHTML = '';
    main.appendChild(mainTitle);

    // --- Add Password Rules Display Area ---
    var rulesDiv = document.createElement('div');
    rulesDiv.style.marginBottom = '1.5em';
    rulesDiv.style.padding = '1em';
    rulesDiv.style.border = '1px solid #ccc';
    rulesDiv.style.borderRadius = '5px';
    rulesDiv.innerHTML = `<h4>New Password Requirements:</h4><ul id="password-rules-list"></ul>`; // Add ul with id
    main.appendChild(rulesDiv);

    // Populate the rules list (initially hidden except the first)
    const rulesListElement = document.getElementById('password-rules-list');
    if (rulesListElement) {
        passwordRules.forEach((rule, index) => {
            const li = document.createElement('li');
            li.id = rule.id;
            li.textContent = rule.text;
            li.style.display = 'none'; // Hide all initially
            rulesListElement.appendChild(li);
        });
        // Show the first rule initially
        const firstRuleElement = document.getElementById(passwordRules[0].id);
         if (firstRuleElement) {
             firstRuleElement.style.display = 'list-item';
             firstRuleElement.style.color = 'red'; // Start as unmet
         }
    }
    // --- End Password Rules Display Area ---


    /* Current Password. */
    var labelCurrentPassword = document.createElement('label');
    labelCurrentPassword.innerText = 'Current password';
    var inputCurrentPassword = document.createElement('input');
    inputCurrentPassword.id = 'currentPassword';
    inputCurrentPassword.type = 'password';
    inputCurrentPassword.autocomplete = 'current-password';
    var divCurrentPassword = document.createElement('div');
    divCurrentPassword.appendChild(labelCurrentPassword);
    divCurrentPassword.innerHTML += '<br>';
    divCurrentPassword.appendChild(inputCurrentPassword);

    /* New Password. */
    var labelPassword = document.createElement('label');
    labelPassword.innerText = 'New password';
    var inputPassword = document.createElement('input');
    inputPassword.id = 'password';
    inputPassword.type = 'password';
    inputPassword.autocomplete = 'new-password';
    // Add event listener to update rules display on input
    inputPassword.addEventListener('input', updatePasswordRulesDisplay);
    var divPassword = document.createElement('div');
    divPassword.innerHTML += '<br>';
    divPassword.appendChild(labelPassword);
    divPassword.innerHTML += '<br>';
    divPassword.appendChild(inputPassword);

    /* Confirm New Password. */
    var labelConfirmPassword = document.createElement('label');
    labelConfirmPassword.innerText = 'Confirm new password';
    var inputConfirmPassword = document.createElement('input');
    inputConfirmPassword.id = 'confirmPassword';
    inputConfirmPassword.type = 'password';
    inputConfirmPassword.autocomplete = 'new-password';
    var divConfirmPassword = document.createElement('div');
    divConfirmPassword.innerHTML += '<br>';
    divConfirmPassword.appendChild(labelConfirmPassword);
    divConfirmPassword.innerHTML += '<br>';
    divConfirmPassword.appendChild(inputConfirmPassword);

    /* Show Password Checkbox */
    var showPasswordCheckbox = document.createElement('input');
    showPasswordCheckbox.type = 'checkbox';
    showPasswordCheckbox.id = 'showPassword';
    showPasswordCheckbox.addEventListener('change', togglePasswordVisibility); // Add event listener
    var showPasswordLabel = document.createElement('label');
    showPasswordLabel.htmlFor = 'showPassword';
    showPasswordLabel.innerText = ' Show Password'; // Add space for visual separation
    showPasswordLabel.style.marginLeft = '5px'; // Add some space before the label text
    var divShowPassword = document.createElement('div');
    divShowPassword.style.marginTop = '0.5em'; // Add a little space above the checkbox
    divShowPassword.appendChild(showPasswordCheckbox);
    divShowPassword.appendChild(showPasswordLabel);
    // --- End Show Password Checkbox ---

    /* Change button. */
    var submitButton = document.createElement('input');
    submitButton.type = 'submit';
    submitButton.value = 'Change Password';
    var divButton = document.createElement('div');
    divButton.style.marginTop = '1em';
    divButton.appendChild(submitButton);

    /* Form. */
    var changePasswordForm = document.createElement('form');
    changePasswordForm.action = 'javascript:onPasswordChange()';
    changePasswordForm.appendChild(divCurrentPassword);
    changePasswordForm.appendChild(divPassword);
    changePasswordForm.appendChild(divConfirmPassword);
    changePasswordForm.appendChild(divShowPassword); // Add the show password checkbox div
    changePasswordForm.appendChild(divButton);

    main.appendChild(changePasswordForm);
    inputCurrentPassword.focus();

    // Initial call to set the state based on empty input (will show first rule as red)
    updatePasswordRulesDisplay();
}