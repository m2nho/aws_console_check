/**
 * Recommendation Card Interactive Features
 * This script adds interactive functionality to the redesigned recommendation cards
 */

document.addEventListener('DOMContentLoaded', function() {
    // Find all recommendation cards
    const recommendationCards = document.querySelectorAll('.recommendation-card');
    
    if (recommendationCards) {
        recommendationCards.forEach(card => {
            // Handle the "Later" button
            const laterBtn = card.querySelector('.btn-later');
            if (laterBtn) {
                laterBtn.addEventListener('click', function(e) {
                    e.preventDefault();
                    
                    // Get the recommendation ID from the data attribute
                    const recId = card.getAttribute('data-recommendation-id');
                    
                    // In a real application, this would mark the recommendation for later review
                    // For now, we'll just hide the card with an animation
                    card.style.opacity = '0';
                    card.style.transform = 'translateY(20px)';
                    
                    setTimeout(() => {
                        card.style.display = 'none';
                        
                        // Show a message that the recommendation was snoozed
                        const container = document.querySelector('.recommendations-container');
                        if (container && container.querySelectorAll('.recommendation-card:not([style*="display: none"])').length === 0) {
                            const noRecsMsg = document.createElement('div');
                            noRecsMsg.className = 'alert alert-info';
                            noRecsMsg.textContent = '모든 권장 사항이 나중으로 미뤄졌습니다. 나중에 다시 확인하세요.';
                            container.appendChild(noRecsMsg);
                        }
                    }, 300);
                });
            }
            
            // Handle toggle details buttons
            const toggleDetailsBtn = card.querySelector('.toggle-details');
            if (toggleDetailsBtn) {
                toggleDetailsBtn.addEventListener('click', function(e) {
                    e.preventDefault();
                    
                    // Get the target details element
                    const targetId = this.getAttribute('data-target');
                    const detailsElement = document.getElementById(targetId);
                    
                    if (detailsElement) {
                        // Toggle the collapse class
                        detailsElement.classList.toggle('show');
                        
                        // Update the button text and icon
                        if (detailsElement.classList.contains('show')) {
                            this.innerHTML = '<i class="fas fa-chevron-up me-1"></i> 간략히 보기';
                            this.classList.remove('btn-outline-primary');
                            this.classList.add('btn-primary');
                        } else {
                            this.innerHTML = '<i class="fas fa-chevron-down me-1"></i> 상세 정보 보기';
                            this.classList.remove('btn-primary');
                            this.classList.add('btn-outline-primary');
                        }
                        
                        // Scroll into view when expanded
                        if (detailsElement.classList.contains('show')) {
                            setTimeout(() => {
                                detailsElement.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                            }, 300);
                        }
                    }
                });
            }
            
            // No longer need expandable sections handling as we're using the dropdown style
        });
    }
});


