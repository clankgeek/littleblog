// Gestion du masquage du header lors du scroll
let lastScrollTop = 0;
const header = document.querySelector('.header');
let scrollTimeout;

window.addEventListener('scroll', () => {
    clearTimeout(scrollTimeout);
    
    scrollTimeout = setTimeout(() => {
        const scrollTop = window.scrollY || document.documentElement.scrollTop;
        
        if (scrollTop > lastScrollTop && scrollTop > 100) {
            // Scroll vers le bas - cacher le header
            header.classList.add('header-hidden');
        } else if (scrollTop < lastScrollTop) {
            // Scroll vers le haut - afficher le header
            header.classList.remove('header-hidden');
        }
        
        lastScrollTop = scrollTop <= 0 ? 0 : scrollTop;
    }, 50);
});
