document.addEventListener('DOMContentLoaded', function () {
    const generatePasswordButton = document.getElementById('generate_password');
    const specialSymbolsCheckbox = document.getElementById('special_symbols');
    const customSymbolsInput = document.getElementById('custom_symbols');
    const specialSymbolsContainer = document.getElementById('special_symbols_container');

    // Скрыть/показать форму ввода специальных символов при переключении чекбокса
    specialSymbolsCheckbox.addEventListener('change', function () {
        if (specialSymbolsCheckbox.checked) {
            specialSymbolsContainer.style.display = 'block';
        } else {
            specialSymbolsContainer.style.display = 'none';
        }
    });

    // Удалить дубликаты из поля custom_symbols
    customSymbolsInput.addEventListener('input', function () {
        const uniqueSymbols = [...new Set(customSymbolsInput.value.split(''))].join('');
        customSymbolsInput.value = uniqueSymbols;
    });

    generatePasswordButton.addEventListener('click', function () {
        const lengthField = document.getElementById('password_length');
        const passwordField = document.getElementById('password');

        const length = parseInt(lengthField.value) || 24;
        if (length < 1 || length > 128) {
            alert('Password length must be between 1 and 128.');
            return;
        }

        let charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        if (specialSymbolsCheckbox.checked) {
            const customSymbols = customSymbolsInput.value || '!@$%^&*()-_+=|:.';
            charset += customSymbols;
        }

        let password = '';
        for (let i = 0; i < length; i++) {
            const randomIndex = Math.floor(Math.random() * charset.length);
            password += charset[randomIndex];
        }

        passwordField.value = password;
    });
});
