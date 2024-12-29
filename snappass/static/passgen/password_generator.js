document.addEventListener('DOMContentLoaded', function () {
    const charCounter = document.getElementById('remaining'); // Элемент счётчика
    const generatePasswordButton = document.getElementById('generate_password');
    const specialSymbolsCheckbox = document.getElementById('special_symbols');
    const customSymbolsInput = document.getElementById('custom_symbols');
    const specialSymbolsContainer = document.getElementById('special_symbols_container');
    const passwordField = document.getElementById('password'); // Поле для пароля
    const maxLength = 4096; // Максимальная длина пароля
    const warningMessageId = 'password_warning'; // ID сообщения предупреждения

    // Список всех допустимых символов
    const allowedSpecialSymbols = '!@#$%^&*()-_=+[]{}<>;:,.?/|\\`\'"~';
    const defaultSpecialSymbols = '!@$%^&*_-#()=+[]{}<>;:,.?';

    // Установить начальное значение для поля customSymbolsInput
    customSymbolsInput.value = defaultSpecialSymbols;

    // Скрыть/показать форму ввода специальных символов при переключении чекбокса
    specialSymbolsCheckbox.addEventListener('change', function () {
        if (specialSymbolsCheckbox.checked) {
            specialSymbolsContainer.style.display = 'block';
        } else {
            specialSymbolsContainer.style.display = 'none';
        }
    });

    // Фильтр допустимых символов
    customSymbolsInput.addEventListener('input', function () {
        // Удалить недопустимые символы
        const filteredSymbols = customSymbolsInput.value
            .split('')
            .filter(char => allowedSpecialSymbols.includes(char));
        // Удалить дубликаты
        const uniqueSymbols = [...new Set(filteredSymbols)].join('');
        customSymbolsInput.value = uniqueSymbols;
    });

    // Обновление счётчика символов
    function updateCharCounter() {
        const remaining = maxLength - passwordField.value.length; // Сколько символов осталось
        charCounter.textContent = remaining >= 0 ? remaining : 0; // Обновляем счётчик
    }

    // Разрешить изменение размера текстового поля
    passwordField.style.resize = 'both';

    // Обновляем счётчик при вводе
    passwordField.addEventListener('input', updateCharCounter);

    generatePasswordButton.addEventListener('click', function () {
        const lengthField = document.getElementById('password_length');

        const length = parseInt(lengthField.value) || 24;
        if (length < 1 || length > 512) {
            alert('Password length must be between 1 and 512.');
            return;
        }

        let charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        if (specialSymbolsCheckbox.checked) {
            const customSymbols = customSymbolsInput.value || allowedSpecialSymbols;
            charset += customSymbols;
        }

        let password = '';
        for (let i = 0; i < length; i++) {
            const randomIndex = Math.floor(Math.random() * charset.length);
            password += charset[randomIndex];
        }

        passwordField.value = password;
        updateCharCounter(); // Обновляем счётчик символов после генерации
    });
});