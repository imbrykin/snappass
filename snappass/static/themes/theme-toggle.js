document.addEventListener('DOMContentLoaded', () => {
    const themeToggle = document.getElementById('theme-toggle');
    const themeIcon = document.getElementById('theme-icon');

    const prefersDarkScheme = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const savedTheme = localStorage.getItem('theme');

    // Устанавливаем тему
    if (savedTheme === 'dark' || (!savedTheme && prefersDarkScheme)) {
        document.body.classList.add('dark-theme');
        themeToggle.checked = true;
        themeIcon.textContent = '🌙';
    } else {
        document.body.classList.remove('dark-theme');
        themeToggle.checked = false;
        themeIcon.textContent = '☀️';
    }

    // Обработка переключения
    themeToggle.addEventListener('change', () => {
        if (themeToggle.checked) {
            document.body.classList.add('dark-theme');
            themeIcon.textContent = '🌙';
            localStorage.setItem('theme', 'dark');
        } else {
            document.body.classList.remove('dark-theme');
            themeIcon.textContent = '☀️'; 
            localStorage.setItem('theme', 'light');
        }
    });
});