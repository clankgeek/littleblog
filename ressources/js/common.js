// Scripts globaux
document.addEventListener('alpine:init', () => {
    // Recherche globale
    Alpine.data('searchComponent', () => ({
        query: '',
        results: [],
        showResults: false,

        async search() {
            if (this.query.length < 2) {
                this.results = [];
                this.showResults = false;
                return;
            }

            try {
                const response = await fetch(`/api/search?q=${encodeURIComponent(this.query)}`);
                if (response.ok) {
                    this.results = await response.json();
                    this.showResults = true;
                }
            } catch (error) {
                console.error('Erreur de recherche:', error);
                this.results = [];
            }
        }
    }));
});

// Fonction de déconnexion globale
async function logout() {
    try {
        const response = await fetch('/admin/logout', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            }
        });

        if (response.ok) {
            window.location.href = '/';
        }
    } catch (error) {
        console.error('Erreur déconnexion:', error);
    }
}

// Utilitaires globaux
window.showNotification = function (message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 20px;
        background: ${type === 'success' ? '#28a745' : type === 'error' ? '#dc3545' : '#007bff'};
        color: white;
        border-radius: 8px;
        z-index: 1000;
        box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        animation: slideIn 0.3s ease-out;
    `;

    document.body.appendChild(notification);

    setTimeout(() => {
        notification.remove();
    }, 4000);
};

// Animation pour les notifications
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
`;
document.head.appendChild(style);
