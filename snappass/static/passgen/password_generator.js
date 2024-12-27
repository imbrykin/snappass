document.addEventListener('DOMContentLoaded', function () {
    const generatePasswordButton = document.getElementById('generate_password');
    if (generatePasswordButton) {
        generatePasswordButton.addEventListener('click', function () {
            const lengthField = document.getElementById('password_length');
            const passwordField = document.getElementById('password');
            
            const length = parseInt(lengthField.value) || 24;
            if (length < 1 || length > 128) {
                alert('Password length must be between 1 and 128.');
                return;
            }

            const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@$%^&*()-_+=|:.';
            let password = '';
            for (let i = 0; i < length; i++) {
                password += charset[Math.floor(Math.random() * charset.length)];
            }

            passwordField.value = password;
        });
    }
});