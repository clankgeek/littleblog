document.addEventListener('alpine:init', () => {
    Alpine.data('loginForm', () => ({
        credentials: {
            username: '',
            password: ''
        },
        loading: false,
        error: '',

        async login() {
            this.loading = true;
            this.error = '';

            try {
                const response = await fetch('/admin/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(this.credentials)
                });

                const data = await response.json();

                if (response.ok) {
                    window.location.href = data.redirect || '/admin';
                } else {
                    this.error = data.error || 'Erreur de connexion';
                }
            } catch (error) {
                console.error('Erreur:', error);
                this.error = 'Erreur de connexion au serveur';
            } finally {
                this.loading = false;
            }
        }
    }));
});