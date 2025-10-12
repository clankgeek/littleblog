// Scripts spécifiques au dashboard
console.log('Dashboard admin chargé');

// Animation des stats au chargement
document.addEventListener('DOMContentLoaded', function () {
    const statNumbers = document.querySelectorAll('.stat-number');

    statNumbers.forEach(stat => {
        const finalValue = parseInt(stat.textContent);
        stat.textContent = '0';

        let current = 0;
        const increment = finalValue / 30;
        const timer = setInterval(() => {
            current += increment;
            if (current >= finalValue) {
                stat.textContent = finalValue;
                clearInterval(timer);
            } else {
                stat.textContent = Math.floor(current);
            }
        }, 50);
    });
});