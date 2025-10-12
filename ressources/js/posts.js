document.addEventListener('alpine:init', () => {
    Alpine.data('postInteractions', (postId) => ({
        postId: postId,
        comments: [],
        showComments: false,
        likeCount: 0,
        isLiked: false,
        loading: false,
        captchaImage: '',
        newComment: {
            author: '',
            content: '',
            captchaID: '',
            captchaAnswer: '',
        },

        async init() {
            await this.loadComments();
        },

        async deleteComment(commentId) {
            try {
                const response = await fetch(`/api/comments/${commentId}`, {
                    method: 'DELETE',
                    headers: {
                        'Content-Type': 'application/json',
                    }
                });

                if (response.ok) {
                    this.comments = this.comments.filter(c => c.id !== commentId);
                    window.showNotification('Commentaire supprimé avec succès !', 'success');
                } else {
                    window.showNotification('Erreur lors de la suppression du commenataire', 'error');
                }
            } catch (error) {
                window.showNotification('Erreur lors de la suppression du commenataire', 'error');
                console.error('Erreur:', error);
            }
        },

        async refreshCaptcha() {
            try {
                const response = await fetch('/files/captcha');
                const data = await response.json();
                this.newComment.captchaID = data.captcha_id;
                this.newComment.captchaAnswer = data.answer;
                this.captchaImage = data.image;
                if (data.answer) {
                    console.log('Réponse du CAPTCHA:', data.answer);
                }
            } catch (error) {
                console.error('Erreur:', error);
                this.showMessage('Erreur de chargement du CAPTCHA', 'error');
            }
        },

        async loadComments() {
            try {
                const response = await fetch(`/api/posts/${this.postId}/comments`);
                if (response.ok) {
                    this.comments = await response.json();
                }
            } catch (error) {
                console.error('Erreur chargement commentaires:', error);
                window.showNotification('Erreur lors du chargement des commentaires', 'error');
            }
        },

        async addComment() {
            if (!this.newComment.author.trim() || !this.newComment.content.trim() || !this.newComment.captchaAnswer.trim()) {
                window.showNotification('Veuillez remplir tous les champs', 'error');
                return;
            }

            this.loading = true;
            try {
                const response = await fetch(`/api/posts/${this.postId}/comments`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(this.newComment)
                });

                if (response.ok) {
                    const comment = await response.json();
                    this.comments.push(comment);
                    this.newComment = { author: '', content: '', captchaId: '', captchaAnswer: '', captchaImage: '' };
                    this.captchaImage = ''
                    window.showNotification('Commentaire ajouté avec succès !', 'success');
                } else {
                    const error = await response.json();
                    window.showNotification('Erreur: ' + error.error, 'error');
                }
            } catch (error) {
                console.error('Erreur ajout commentaire:', error);
                window.showNotification('Erreur lors de l\'ajout du commentaire', 'error');
            } finally {
                this.loading = false;
            }
        },

        formatDate(dateStr) {
            const date = new Date(dateStr);
            return date.toLocaleDateString('fr-FR', {
                day: '2-digit',
                month: 'long',
                year: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            });
        }
    }));
});