document.addEventListener('alpine:init', () => {
    Alpine.data('postsManager', () => ({
        showDeleteModal: false,
        deleteTarget: { id: null, title: '' },
        deleting: false,

        confirmDelete(id, title) {
            this.deleteTarget = { id, title };
            this.showDeleteModal = true;
        },

        async deletePost() {
            this.deleting = true;

            try {
                const response = await fetch(`/admin/posts/${this.deleteTarget.id}`, {
                    method: 'DELETE',
                    headers: {
                        'Content-Type': 'application/json',
                    }
                });

                const data = await response.json();

                if (response.ok) {
                    this.showDeleteModal = false;
                    window.showNotification('Article supprimé avec succès', 'success');

                    // Recharger la page après un court délai
                    setTimeout(() => {
                        location.reload();
                    }, 1000);
                } else {
                    window.showNotification('Erreur: ' + data.error, 'error');
                }
            } catch (error) {
                console.error('Erreur suppression:', error);
                window.showNotification('Erreur lors de la suppression', 'error');
            } finally {
                this.deleting = false;
            }
        }
    }));
});