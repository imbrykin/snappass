document.addEventListener('DOMContentLoaded', function () {
    const charCounter = document.getElementById('remaining');
    const generatePasswordButton = document.getElementById('generate_password');
    const specialSymbolsCheckbox = document.getElementById('special_symbols');
    const customSymbolsInput = document.getElementById('custom_symbols');
    const specialSymbolsContainer = document.getElementById('special_symbols_container');
    const passwordField = document.getElementById('password');
    const passwordLengthInput = document.getElementById('password_length');
    const passwordSlider = document.getElementById('password_slider');

    const maxLength = 4096;
    const allowedSpecialSymbols = '!@#$%^&*()-_=+[]{}<>;:,.?/|\\`\'"~';
    const defaultSpecialSymbols = '!@$%^&*_-#()=+[]{}<>;:,.?';
    const presetSteps = [8, 16, 24, 32, 40, 48, 56, 64];

    function updateCharCounter() {
        const remaining = maxLength - passwordField.value.length;
        charCounter.textContent = Math.max(remaining, 0);
    }

    function syncSliderAndInput(value) {
        const sanitizedValue = Math.min(Math.max(value, 1), 64); // Ensure within range
        const closestStep = presetSteps.reduce((prev, curr) =>
            Math.abs(curr - sanitizedValue) < Math.abs(prev - sanitizedValue) ? curr : prev
        );
        passwordLengthInput.value = sanitizedValue;
        passwordSlider.value = closestStep;
    }

    function sanitizeCustomSymbols() {
        const filteredSymbols = customSymbolsInput.value
            .split('')
            .filter(char => allowedSpecialSymbols.includes(char));
        customSymbolsInput.value = [...new Set(filteredSymbols)].join('');
    }

    specialSymbolsCheckbox.addEventListener('change', function () {
        specialSymbolsContainer.style.display = specialSymbolsCheckbox.checked ? 'block' : 'none';
    });

    customSymbolsInput.addEventListener('input', sanitizeCustomSymbols);

    passwordField.addEventListener('input', updateCharCounter);

    passwordLengthInput.addEventListener('input', function () {
        const value = parseInt(this.value, 10) || 1;
        syncSliderAndInput(value);
    });

    passwordSlider.addEventListener('input', function () {
        const value = parseInt(this.value, 10);
        const closestStep = presetSteps.reduce((prev, curr) =>
            Math.abs(curr - value) < Math.abs(prev - value) ? curr : prev
        );
        passwordSlider.value = closestStep;
        passwordLengthInput.value = closestStep;
    });

    generatePasswordButton.addEventListener('click', function () {
        const length = parseInt(passwordLengthInput.value, 10) || 8;
        if (length < 1 || length > 64) {
            alert('Password length must be between 1 and 64.');
            return;
        }

        let charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        if (specialSymbolsCheckbox.checked) {
            charset += customSymbolsInput.value.trim() || '';
        }

        let password = '';
        for (let i = 0; i < length; i++) {
            const randomIndex = Math.floor(Math.random() * charset.length);
            password += charset[randomIndex];
        }

        passwordField.value = password;
        updateCharCounter();
    });

    // Initialize fields
    customSymbolsInput.value = defaultSpecialSymbols;
    syncSliderAndInput(parseInt(passwordLengthInput.value, 10) || 8);
    updateCharCounter();
});