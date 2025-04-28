/**
 * Modal backdrop fix for AWS Console Check application
 * This script specifically addresses the issue with modal backdrops
 * when clicking on recommendation detail buttons
 */

document.addEventListener('DOMContentLoaded', function() {
    // Find all recommendation detail buttons
    const detailButtons = document.querySelectorAll('.btn-sm.btn-info[data-bs-toggle="modal"]');
    
    if (detailButtons) {
        detailButtons.forEach(button => {
            button.addEventListener('click', function(event) {
                // Get the target modal ID
                const targetModalId = this.getAttribute('data-bs-target').substring(1);
                const targetModal = document.getElementById(targetModalId);
                
                if (targetModal) {
                    // Remove any existing backdrops
                    const existingBackdrops = document.querySelectorAll('.modal-backdrop');
                    existingBackdrops.forEach(backdrop => backdrop.remove());
                    
                    // Remove modal-open class from body if it exists
                    document.body.classList.remove('modal-open');
                    
                    // Create a new backdrop
                    const backdrop = document.createElement('div');
                    backdrop.className = 'modal-backdrop fade show';
                    backdrop.style.zIndex = '1040'; // Set explicit z-index for backdrop
                    backdrop.dataset.modalId = targetModalId;
                    document.body.appendChild(backdrop);
                    
                    // Add modal-open class to body
                    document.body.classList.add('modal-open');
                    
                    // Add padding-right to body to prevent layout shift
                    document.body.style.paddingRight = '17px';
                    
                    // Ensure the modal has the correct classes and z-index
                    targetModal.classList.add('show');
                    targetModal.setAttribute('aria-modal', 'true');
                    targetModal.setAttribute('role', 'dialog');
                    targetModal.style.display = 'block';
                    targetModal.style.zIndex = '1050'; // Set explicit z-index for modal
                    
                    // Prevent the default behavior to take full control
                    event.preventDefault();
                    event.stopPropagation();
                    
                    // Add event listener to close button
                    const closeButtons = targetModal.querySelectorAll('[data-bs-dismiss="modal"]');
                    closeButtons.forEach(closeButton => {
                        closeButton.addEventListener('click', function() {
                            // Remove the backdrop
                            const modalBackdrop = document.querySelector(`.modal-backdrop[data-modal-id="${targetModalId}"]`);
                            if (modalBackdrop) {
                                modalBackdrop.remove();
                            }
                            
                            // Remove modal-open class from body
                            document.body.classList.remove('modal-open');
                            
                            // Remove padding-right from body
                            document.body.style.paddingRight = '';
                            
                            // Hide the modal
                            targetModal.classList.remove('show');
                            targetModal.removeAttribute('aria-modal');
                            targetModal.removeAttribute('role');
                            targetModal.style.display = 'none';
                        });
                    });
                }
            });
        });
    }
    
    // Handle ESC key to close modals
    document.addEventListener('keydown', function(event) {
        if (event.key === 'Escape') {
            const openModals = document.querySelectorAll('.modal.show');
            if (openModals.length > 0) {
                openModals.forEach(modal => {
                    // Get the modal ID
                    const modalId = modal.id;
                    
                    // Remove the backdrop
                    const modalBackdrop = document.querySelector(`.modal-backdrop[data-modal-id="${modalId}"]`);
                    if (modalBackdrop) {
                        modalBackdrop.remove();
                    }
                    
                    // Remove modal-open class from body if this is the last open modal
                    if (openModals.length === 1) {
                        document.body.classList.remove('modal-open');
                        document.body.style.paddingRight = '';
                    }
                    
                    // Hide the modal
                    modal.classList.remove('show');
                    modal.removeAttribute('aria-modal');
                    modal.removeAttribute('role');
                    modal.style.display = 'none';
                });
            }
        }
    });
});
