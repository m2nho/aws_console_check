// Main JavaScript file for AWS Console Check application

document.addEventListener('DOMContentLoaded', function() {
    // Add event listener for password visibility toggle
    const togglePasswordButtons = document.querySelectorAll('.toggle-password');
    if (togglePasswordButtons) {
        togglePasswordButtons.forEach(button => {
            button.addEventListener('click', function() {
                const passwordInput = document.querySelector(this.getAttribute('data-target'));
                if (passwordInput.type === 'password') {
                    passwordInput.type = 'text';
                    this.textContent = '숨기기';
                } else {
                    passwordInput.type = 'password';
                    this.textContent = '보기';
                }
            });
        });
    }

    // Add tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    if (tooltipTriggerList.length > 0) {
        tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    }

    // Add confirmation for logout
    const logoutLink = document.querySelector('a[href*="logout"]');
    if (logoutLink) {
        logoutLink.addEventListener('click', function(e) {
            if (!confirm('로그아웃 하시겠습니까?')) {
                e.preventDefault();
            }
        });
    }

    // Add sorting functionality to tables
    const tables = document.querySelectorAll('.table-sortable');
    if (tables) {
        tables.forEach(table => {
            const headers = table.querySelectorAll('th');
            headers.forEach((header, index) => {
                header.addEventListener('click', function() {
                    sortTable(table, index);
                });
                header.style.cursor = 'pointer';
                header.title = '클릭하여 정렬';
            });
        });
    }
    
    // Enhance modal behavior to prevent background interaction
    const modals = document.querySelectorAll('.modal');
    if (modals) {
        modals.forEach(modal => {
            modal.addEventListener('show.bs.modal', function() {
                // Add a class to the body to prevent scrolling
                document.body.classList.add('modal-open');
                
                // Remove any existing backdrop before creating a new one
                const existingBackdrop = document.querySelector('.modal-backdrop');
                if (existingBackdrop) {
                    existingBackdrop.remove();
                }
                
                // Create a new backdrop
                const backdrop = document.createElement('div');
                backdrop.className = 'modal-backdrop fade show';
                document.body.appendChild(backdrop);
                
                // Add a unique identifier to the backdrop for this modal
                backdrop.dataset.modalId = this.id;
            });
            
            modal.addEventListener('hidden.bs.modal', function() {
                // Check if there are other open modals before removing modal-open class
                const openModals = document.querySelectorAll('.modal.show');
                if (openModals.length <= 1) { // Only the current one that's being closed
                    document.body.classList.remove('modal-open');
                }
                
                // Remove the backdrop associated with this modal
                const backdrop = document.querySelector(`.modal-backdrop[data-modal-id="${this.id}"]`);
                if (backdrop) {
                    backdrop.remove();
                } else {
                    // Fallback: remove any backdrop if the specific one can't be found
                    const anyBackdrop = document.querySelector('.modal-backdrop');
                    if (anyBackdrop) {
                        anyBackdrop.remove();
                    }
                }
            });
            
            // Prevent clicks on the modal from propagating to elements behind it
            modal.addEventListener('click', function(event) {
                event.stopPropagation();
            });
        });
    }
});

// Function to sort tables
function sortTable(table, column) {
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    const direction = table.getAttribute('data-sort-direction') === 'asc' ? -1 : 1;
    
    // Sort the rows
    rows.sort((a, b) => {
        const aValue = a.querySelectorAll('td')[column].textContent.trim();
        const bValue = b.querySelectorAll('td')[column].textContent.trim();
        
        if (!isNaN(aValue) && !isNaN(bValue)) {
            return direction * (Number(aValue) - Number(bValue));
        } else {
            return direction * aValue.localeCompare(bValue, 'ko');
        }
    });
    
    // Update the table
    rows.forEach(row => tbody.appendChild(row));
    
    // Toggle the sort direction
    table.setAttribute('data-sort-direction', direction === 1 ? 'asc' : 'desc');
}

