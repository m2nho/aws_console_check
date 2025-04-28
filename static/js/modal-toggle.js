/**
 * Modal toggle functionality for AWS Console Check application
 * This script makes modal buttons toggle the modal instead of just opening it
 */

document.addEventListener('DOMContentLoaded', function() {
    // Find all recommendation detail buttons
    const detailButtons = document.querySelectorAll('.btn-sm.btn-info[data-bs-toggle="modal"]');
    
    if (detailButtons) {
        detailButtons.forEach(button => {
            // Store the original text
            const originalText = button.textContent.trim();
            
            // Create a flag to track modal state
            button.setAttribute('data-modal-open', 'false');
            
            button.addEventListener('click', function(event) {
                // Get the target modal ID
                const targetModalId = this.getAttribute('data-bs-target').substring(1);
                const targetModal = document.getElementById(targetModalId);
                
                if (targetModal) {
                    // Check if the modal is currently open
                    const isModalOpen = this.getAttribute('data-modal-open') === 'true';
                    
                    if (isModalOpen) {
                        // Modal is open, so close it
                        
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
                        
                        // Update button text and state
                        button.textContent = originalText;
                        button.setAttribute('data-modal-open', 'false');
                        
                        // Prevent default behavior
                        event.preventDefault();
                        event.stopPropagation();
                    } else {
                        // Modal is closed, so open it
                        
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
                        
                        // Update button text and state
                        button.textContent = '닫기';
                        button.setAttribute('data-modal-open', 'true');
                        
                        // Prevent default behavior
                        event.preventDefault();
                        event.stopPropagation();
                    }
                }
            });
            
            // Add event listeners to close buttons inside the modal
            const targetModalId = button.getAttribute('data-bs-target').substring(1);
            const targetModal = document.getElementById(targetModalId);
            
            if (targetModal) {
                const closeButtons = targetModal.querySelectorAll('[data-bs-dismiss="modal"]');
                closeButtons.forEach(closeButton => {
                    closeButton.addEventListener('click', function() {
                        // Update the toggle button state when modal is closed via close button
                        button.textContent = originalText;
                        button.setAttribute('data-modal-open', 'false');
                    });
                });
            }
        });
    }
    
    // Handle ESC key to close modals and update button states
    document.addEventListener('keydown', function(event) {
        if (event.key === 'Escape') {
            const openModals = document.querySelectorAll('.modal.show');
            if (openModals.length > 0) {
                openModals.forEach(modal => {
                    // Get the modal ID
                    const modalId = modal.id;
                    
                    // Find the button that opens this modal
                    const button = document.querySelector(`[data-bs-target="#${modalId}"]`);
                    if (button) {
                        // Reset button text and state
                        const originalText = button.textContent === '닫기' ? '상세 보기' : button.textContent;
                        button.textContent = originalText;
                        button.setAttribute('data-modal-open', 'false');
                    }
                });
            }
        }
    });
});