/**
 * Toggle functionality for recommendation details
 * This script enhances the collapse/expand behavior for recommendation details
 */

document.addEventListener('DOMContentLoaded', function() {
    // Find all recommendation detail buttons
    const detailButtons = document.querySelectorAll('button[data-bs-toggle="collapse"]');
    
    if (detailButtons) {
        detailButtons.forEach(button => {
            // Store the original text
            const originalText = button.textContent.trim();
            
            // Get the target collapse ID
            const targetCollapseId = button.getAttribute('data-bs-target').substring(1);
            const targetCollapse = document.getElementById(targetCollapseId);
            
            if (targetCollapse) {
                // Initialize Bootstrap collapse
                const bsCollapse = new bootstrap.Collapse(targetCollapse, {
                    toggle: false
                });
                
                // Add click event listener to the button
                button.addEventListener('click', function() {
                    if (targetCollapse.classList.contains('show')) {
                        // If it's open, close it
                        bsCollapse.hide();
                    } else {
                        // If it's closed, open it
                        bsCollapse.show();
                    }
                });
                
                // Add event listener for when collapse is shown
                targetCollapse.addEventListener('shown.bs.collapse', function() {
                    button.textContent = '닫기';
                    button.classList.remove('btn-outline-primary');
                    button.classList.add('btn-primary');
                });
                
                // Add event listener for when collapse is hidden
                targetCollapse.addEventListener('hidden.bs.collapse', function() {
                    button.textContent = originalText;
                    button.classList.remove('btn-primary');
                    button.classList.add('btn-outline-primary');
                });
            }
        });
    }
    
    // Find all toggle-details buttons (our new implementation)
    const toggleButtons = document.querySelectorAll('.toggle-details');
    
    if (toggleButtons) {
        toggleButtons.forEach(button => {
            // Get the target details element
            const targetId = button.getAttribute('data-target');
            const detailsElement = document.getElementById(targetId);
            
            if (detailsElement) {
                // Add click event listener to the button
                button.addEventListener('click', function(e) {
                    e.preventDefault();
                    
                    // Toggle the collapse class
                    detailsElement.classList.toggle('show');
                    
                    // Update the button text and icon
                    const icon = this.querySelector('i');
                    if (detailsElement.classList.contains('show')) {
                        this.innerHTML = '<i class="fas fa-chevron-up me-1"></i> 간략히 보기';
                        this.classList.remove('btn-outline-primary');
                        this.classList.add('btn-primary');
                        
                        // Automatically expand all sections when details are shown
                        const expandableSections = detailsElement.querySelectorAll('.expandable-section');
                        expandableSections.forEach(section => {
                            const content = section.querySelector('.section-content');
                            const header = section.querySelector('.section-header');
                            const icon = header.querySelector('.toggle-icon');
                            
                            // Add expanded class
                            section.classList.add('expanded');
                            
                            // Update icon
                            if (icon) {
                                icon.classList.remove('fa-chevron-down');
                                icon.classList.add('fa-chevron-up');
                            }
                            
                            // Set content height
                            if (content) {
                                content.style.maxHeight = content.scrollHeight + 'px';
                            }
                        });
                    } else {
                        this.innerHTML = '<i class="fas fa-chevron-down me-1"></i> 상세 정보 보기';
                        this.classList.remove('btn-primary');
                        this.classList.add('btn-outline-primary');
                        
                        // Collapse all sections when details are hidden
                        const expandableSections = detailsElement.querySelectorAll('.expandable-section');
                        expandableSections.forEach(section => {
                            const content = section.querySelector('.section-content');
                            const header = section.querySelector('.section-header');
                            const icon = header.querySelector('.toggle-icon');
                            
                            // Remove expanded class
                            section.classList.remove('expanded');
                            
                            // Update icon
                            if (icon) {
                                icon.classList.remove('fa-chevron-up');
                                icon.classList.add('fa-chevron-down');
                            }
                            
                            // Reset content height
                            if (content) {
                                content.style.maxHeight = '0';
                            }
                        });
                    }
                });
            }
        });
    }
});
