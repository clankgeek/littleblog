function infiniteScroll(category, isAuthenticated) {
    return {
        category: category,
        isAuthenticated: isAuthenticated,
        posts: [],
        loading: false,
        hasMore: true,
        page: 1,
        perPage: 5,
        observer: null,

        async init() {
            // Charger les premiers articles
            await this.loadPosts();

            // Configurer l'Intersection Observer
            this.setupObserver();
        },

        setupObserver() {
            const options = {
                root: null,
                rootMargin: '100px',
                threshold: 0.1
            };

            this.observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting && !this.loading && this.hasMore) {
                        this.loadPosts();
                    }
                });
            }, options);

            // Observer le sentinel
            if (this.$refs.sentinel) {
                this.observer.observe(this.$refs.sentinel);
            }
        },

        async loadPosts() {
            if (this.loading || !this.hasMore) return;

            this.loading = true;

            // Afficher des skeletons pendant le chargement
            this.showSkeletons();

            try {
                // Appel API pour récupérer les articles
                const response = await fetch(`/api/posts?page=${this.page}&limit=${this.perPage}&category=${this.category}`);
                const data = await response.json();

                // Retirer les skeletons
                this.removeSkeletons();

                if (data.posts && data.posts.length > 0) {
                    // Ajouter les nouveaux articles
                    data.posts.forEach(post => {
                        this.renderArticle(post);
                        this.posts.push(post);
                    });

                    this.page++;
                    this.hasMore = data.hasMore || (data.posts.length === this.perPage);
                } else {
                    this.hasMore = false;
                }
            } catch (error) {
                console.error('Erreur lors du chargement des articles:', error);
                this.removeSkeletons();
            } finally {
                this.loading = false;
            }
        },

        renderArticle(post) {
            const template = document.getElementById('article-template');
            const clone = template.content.cloneNode(true);
            const article = clone.querySelector('.article-card');

            // Remplir les données
            const titleLink = article.querySelector('[data-href]');
            titleLink.href = `/post/${post.ID || post.id}`;
            titleLink.textContent = post.title;

            article.querySelector('[data-author]').textContent = post.author || 'Anonyme';
            article.querySelector('[data-date]').textContent = this.formatDate(post.created_at);
            article.querySelector('[data-excerpt]').textContent = post.excerpt || '';
            article.querySelector('[data-comments]').textContent = (post.comments || []).length;

            if (post.image) {
                article.querySelector('.article-body').dataset.image = post.image;
            }

            const readMore = article.querySelector('[data-readmore]');
            readMore.href = `/post/${post.ID || post.id}`;

            // Tags
            const tagsContainer = article.querySelector('[data-tags]');
            const tags = post.TagsList || post.tagsList || [];
            tags.forEach(tag => {
                const tagEl = document.createElement('span');
                tagEl.className = 'tag';
                tagEl.textContent = tag;
                tagsContainer.appendChild(tagEl);
            });

            // Admin actions
            if (this.isAuthenticated) {
                const adminSection = article.querySelector('[data-admin]');
                adminSection.style.display = 'block';
                const editLink = article.querySelector('[data-edit]');
                editLink.href = `/admin/posts/${post.ID || post.id}/edit`;
            }

            // Ajouter au conteneur
            document.getElementById('articles-container').appendChild(clone);
        },

        showSkeletons() {
            const template = document.getElementById('skeleton-template');
            const container = document.getElementById('articles-container');

            for (let i = 0; i < 2; i++) {
                const clone = template.content.cloneNode(true);
                const skeleton = clone.querySelector('.article-skeleton');
                skeleton.classList.add('skeleton-loader');
                container.appendChild(clone);
            }
        },

        removeSkeletons() {
            const skeletons = document.querySelectorAll('.skeleton-loader');
            skeletons.forEach(skeleton => skeleton.remove());
        },

        formatDate(dateString) {
            if (!dateString) return '';
            const date = new Date(dateString);
            return date.toLocaleString('fr-FR', {
                day: '2-digit',
                month: '2-digit',
                year: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                hour12: false
            });
        }
    };
}