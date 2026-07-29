document.addEventListener('alpine:init', () => {
    Alpine.data('postInteractions', (postId, isAdmin = false, adminName = '') => ({
        postId: postId,
        isAdmin: isAdmin,
        adminName: adminName,
        comments: [],
        showComments: false,
        likeCount: 0,
        isLiked: false,
        loading: false,
        captchaImage: '',
        replyTo: null,
        hasMoreComments: false,
        newComment: {
            author: '',
            content: '',
            captchaID: '',
            captchaAnswer: '',
            parentID: null,
        },

        async init() {
            if (this.isAdmin) {
                this.newComment.author = this.adminName;
            }
            await this.loadComments();
        },

        // Dégradé bas de liste tant qu'il reste des commentaires à faire défiler
        updateScrollState() {
            const el = this.$refs.commentsList;
            if (!el) {
                this.hasMoreComments = false;
                return;
            }
            this.hasMoreComments = el.scrollHeight - el.scrollTop - el.clientHeight > 8;
        },

        // L'admin connecté n'a ni pseudo ni captcha à saisir
        get canSubmit() {
            if (!this.newComment.content.trim()) {
                return false;
            }
            if (this.isAdmin) {
                return true;
            }
            return !!this.newComment.author.trim() && !!this.newComment.captchaAnswer.trim();
        },

        // Regroupe les commentaires en fils : racines + réponses ordonnées par date
        get threads() {
            const byId = new Map(this.comments.map(c => [c.id, c]));
            const replies = new Map();
            const roots = [];

            for (const comment of this.comments) {
                // Une réponse dont le parent n'est pas visible est affichée en racine
                if (comment.parent_id && byId.has(comment.parent_id)) {
                    if (!replies.has(comment.parent_id)) {
                        replies.set(comment.parent_id, []);
                    }
                    replies.get(comment.parent_id).push(comment);
                } else {
                    roots.push(comment);
                }
            }

            return roots.map(root => ({
                ...root,
                replies: replies.get(root.id) || []
            }));
        },

        startReply(comment) {
            this.replyTo = comment;
            this.newComment.parentID = comment.id;
            this.$nextTick(() => {
                this.$refs.commentForm?.scrollIntoView({ behavior: 'smooth', block: 'center' });
            });
        },

        cancelReply() {
            this.replyTo = null;
            this.newComment.parentID = null;
        },

        async deleteComment(commentId) {
            try {
                const response = await fetch(`/admin/api/moderation/comments/${commentId}`, {
                    method: 'DELETE'
                });

                if (response.ok) {
                    // Le serveur supprime aussi les réponses
                    this.comments = this.comments.filter(c => c.id !== commentId && c.parent_id !== commentId);
                    if (this.replyTo && this.replyTo.id === commentId) {
                        this.cancelReply();
                    }
                    this.$nextTick(() => this.updateScrollState());
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
                    this.$nextTick(() => this.updateScrollState());
                }
            } catch (error) {
                console.error('Erreur chargement commentaires:', error);
                window.showNotification('Erreur lors du chargement des commentaires', 'error');
            }
        },

        async addComment() {
            if (!this.canSubmit) {
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
                    this.newComment = {
                        author: this.isAdmin ? this.adminName : '',
                        content: '',
                        captchaID: '',
                        captchaAnswer: '',
                        parentID: null,
                    };
                    this.replyTo = null;
                    this.captchaImage = ''
                    this.$nextTick(() => this.updateScrollState());
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