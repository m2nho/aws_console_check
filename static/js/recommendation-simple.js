/**
 * Simplified Recommendation Page JavaScript
 * Handles filtering, toggle functionality, and sidebar navigation
 */

document.addEventListener('DOMContentLoaded', function() {
    // Filter functionality
    const filterButtons = document.querySelectorAll('.filter-btn');
    const recommendationItems = document.querySelectorAll('.recommendation-item');
    const navItems = document.querySelectorAll('.recommendation-nav-item');
    
    filterButtons.forEach(button => {
        button.addEventListener('click', function() {
            // Update active button styling
            filterButtons.forEach(btn => btn.classList.remove('active'));
            this.classList.add('active');
            
            const filter = this.getAttribute('data-filter');
            
            // Filter recommendation items
            recommendationItems.forEach(item => {
                if (filter === 'all' || item.getAttribute('data-service') === filter) {
                    item.style.display = 'block';
                } else {
                    item.style.display = 'none';
                }
            });
            
            // Filter navigation items
            navItems.forEach(item => {
                if (filter === 'all' || item.getAttribute('data-service') === filter) {
                    item.style.display = 'flex';
                } else {
                    item.style.display = 'none';
                }
            });
        });
    });
    
    // Toggle details functionality
    const toggleButtons = document.querySelectorAll('.toggle-details');
    
    toggleButtons.forEach(button => {
        button.addEventListener('click', function() {
            const expanded = this.getAttribute('aria-expanded') === 'true';
            
            // Icon rotation is handled by CSS
            
            if (!expanded) {
                // Scroll into view when expanded
                const card = this.closest('.card');
                setTimeout(() => {
                    card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                }, 300);
            }
        });
    });
    
    // Sidebar navigation functionality
    navItems.forEach(item => {
        item.addEventListener('click', function(e) {
            // Remove active class from all nav items
            navItems.forEach(navItem => navItem.classList.remove('active'));
            
            // Add active class to clicked nav item
            this.classList.add('active');
            
            // Get the target recommendation item
            const targetId = this.getAttribute('href');
            const targetItem = document.querySelector(targetId);
            
            // Smooth scroll to the target item
            if (targetItem) {
                setTimeout(() => {
                    targetItem.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }, 100);
            }
        });
    });
    
    // Highlight active nav item on scroll
    const observerOptions = {
        root: null,
        rootMargin: '0px',
        threshold: 0.5
    };
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const id = entry.target.getAttribute('id');
                const navItem = document.querySelector(`.recommendation-nav-item[href="#${id}"]`);
                
                if (navItem) {
                    navItems.forEach(item => item.classList.remove('active'));
                    navItem.classList.add('active');
                }
            }
        });
    }, observerOptions);
    
    recommendationItems.forEach(item => {
        observer.observe(item);
    });
});
