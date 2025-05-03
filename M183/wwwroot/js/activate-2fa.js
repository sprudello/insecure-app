async function loadSetupInfo() {
    // Use getUserData from login.js (globally available)
    const user = getUserData();
    if (!user || !user.token) {
        toastr.error('You must be logged in.', 'Error');
        // Redirect or show login form based on your app's logic
        // For simplicity, redirecting to login prompt:
        window.location.href = 'index.html?page=login';
        return;
    }

    try {
        const response = await fetch('/api/TwoFactorAuth/setup', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${user.token}`,
                'Accept': 'application/json'
            }
        });

        if (response.ok) {
            const data = await response.json();
            // Check if elements exist before setting values
            const qrCodeImage = document.getElementById('qr-code-image');
            const manualEntryKey = document.getElementById('manual-entry-key');
            if (qrCodeImage) qrCodeImage.src = data.qrCodeImageUrl;
            if (manualEntryKey) manualEntryKey.textContent = data.manualEntryKey;
        } else {
            const errorText = await response.text();
            toastr.error(`Failed to load 2FA setup: ${errorText}`, 'Error');
            const setupInstructions = document.getElementById('setup-instructions');
            if (setupInstructions) setupInstructions.innerHTML = '<p class="warning">Could not load 2FA setup information.</p>';
            const verificationSection = document.getElementById('verification-section');
            if (verificationSection) verificationSection.style.display = 'none';
        }
    } catch (error) {
        console.error('Error fetching 2FA setup:', error);
        toastr.error('An error occurred while fetching 2FA setup information.', 'Error');
    }
}

async function verifyCode() {
    const codeInput = document.getElementById('tfa-code');
    const code = codeInput ? codeInput.value.trim() : '';
    const errorMessageDiv = document.getElementById('error-message');
    if (errorMessageDiv) errorMessageDiv.classList.add('hidden'); // Hide previous errors

    if (!code) {
        toastr.warning('Please enter the verification code.', 'Warning');
        return;
    }

    // Use getUserData from login.js
    const user = getUserData();
    if (!user || !user.token) {
        toastr.error('Session expired. Please log in again.', 'Error');
        window.location.href = 'index.html?page=login';
        return;
    }

    try {
        const response = await fetch('/api/TwoFactorAuth/verify', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${user.token}`,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({ code: code })
        });

        if (response.ok) {
            toastr.success('Two-Factor Authentication enabled successfully!', 'Success');
            // Redirect to home after a short delay
            setTimeout(() => { window.location.href = 'index.html'; }, 2000);
        } else {
            const errorText = await response.text();
            if (errorMessageDiv) {
                errorMessageDiv.textContent = `Verification failed: ${errorText}`;
                errorMessageDiv.classList.remove('hidden');
            }
            toastr.error(`Verification failed: ${errorText}`, 'Error');
        }
    } catch (error) {
        console.error('Error verifying 2FA code:', error);
        if (errorMessageDiv) {
            errorMessageDiv.textContent = 'An unexpected error occurred.';
            errorMessageDiv.classList.remove('hidden');
        }
        toastr.error('An unexpected error occurred during verification.', 'Error');
    }
}

// Function to dynamically create the 2FA activation form
function createActivate2faForm() {
    var main = document.getElementById("main");
    if (!main) return; // Exit if main element doesn't exist

    main.innerHTML = ''; // Clear existing content

    var mainTitle = document.createElement("h1");
    mainTitle.innerText = "Activate Two-Factor Authentication";
    main.appendChild(mainTitle);

    // Setup Instructions Section
    var setupDiv = document.createElement('div');
    setupDiv.id = 'setup-instructions';
    setupDiv.innerHTML = `
        <p>Scan the QR code below with your authenticator app (e.g., Google Authenticator, Authy).</p>
        <div id="qr-code-container" style="margin: 1em 0;">
            <img id="qr-code-image" src="" alt="QR Code Loading..." style="display: block; margin: auto; max-width: 200px; height: auto;" />
        </div>
        <p>If you cannot scan the code, manually enter this key:</p>
        <p><strong id="manual-entry-key" style="word-wrap: break-word;">Loading...</strong></p>
    `;
    main.appendChild(setupDiv);

    main.appendChild(document.createElement('hr'));

    // Verification Section
    var verifyDiv = document.createElement('div');
    verifyDiv.id = 'verification-section';
    verifyDiv.innerHTML = `
        <p>Enter the code from your authenticator app to verify and enable 2FA:</p>
        <form id="verify-form" action="javascript:verifyCode()">
            <div>
                <label for="tfa-code">Verification Code:</label><br/>
                <input type="text" id="tfa-code" name="tfa-code" required autocomplete="off" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" />
            </div>
            <br/>
            <div>
                <button type="submit">Verify and Enable</button>
            </div>
        </form>
        <div id="error-message" class="warning hidden" style="margin-top: 1em;"></div>
    `;
    main.appendChild(verifyDiv);

    // Load the QR code and key
    loadSetupInfo();
}