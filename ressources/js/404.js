document.addEventListener('alpine:init', () => {
    Alpine.data('errorPage', () => ({
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

// Ajouter un peu d'interactivité fun
document.addEventListener('DOMContentLoaded', function () {
    // Effet de parallax léger sur les éléments de background
    window.addEventListener('mousemove', function (e) {
        const elements = document.querySelectorAll('.bg-element');
        const x = e.clientX / window.innerWidth;
        const y = e.clientY / window.innerHeight;

        elements.forEach((el, index) => {
            const speed = (index + 1) * 0.5;
            const xPos = (x - 0.5) * speed * 20;
            const yPos = (y - 0.5) * speed * 20;
            el.style.transform = `translate(${xPos}px, ${yPos}px)`;
        });
    });

    // Easter egg : clic sur le 404
    document.querySelector('.error-code').addEventListener('click', function () {
        this.style.animation = 'none';
        setTimeout(() => {
            this.style.animation = 'bounce 0.6s ease-in-out';
        }, 10);
    });
});