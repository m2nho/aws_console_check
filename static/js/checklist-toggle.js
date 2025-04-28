/**
 * Checklist toggle functionality for AWS Console Check application
 * This script handles the toggle functionality for checklist items
 */

document.addEventListener('DOMContentLoaded', function() {
    // Find all checklist toggle switches
    const toggleSwitches = document.querySelectorAll('.form-check-input[data-item-id]');
    
    if (toggleSwitches.length > 0) {
        // Load saved toggle states from localStorage
        loadToggleStates();
        
        // Add event listeners to toggle switches
        toggleSwitches.forEach(toggle => {
            toggle.addEventListener('change', function() {
                const itemId = this.getAttribute('data-item-id');
                const isChecked = this.checked;
                
                // Save the toggle state to localStorage
                saveToggleState(itemId, isChecked);
                
                // Update the UI
                updateItemUI(itemId, isChecked);
            });
        });
    }
});

/**
 * Load saved toggle states from localStorage
 */
function loadToggleStates() {
    // Get the current service name from the URL
    const serviceName = window.location.pathname.split('/').pop();
    
    // Get saved toggle states from localStorage
    const savedStates = JSON.parse(localStorage.getItem(`checklist-${serviceName}`)) || {};
    
    // Apply saved states to toggle switches
    Object.keys(savedStates).forEach(itemId => {
        const toggle = document.getElementById(`toggle-${itemId}`);
        if (toggle) {
            toggle.checked = savedStates[itemId];
            updateItemUI(itemId, savedStates[itemId]);
        }
    });
}

/**
 * Save toggle state to localStorage
 * @param {string} itemId - The ID of the checklist item
 * @param {boolean} isChecked - Whether the item is checked
 */
function saveToggleState(itemId, isChecked) {
    // Get the current service name from the URL
    const serviceName = window.location.pathname.split('/').pop();
    
    // Get existing saved states
    const savedStates = JSON.parse(localStorage.getItem(`checklist-${serviceName}`)) || {};
    
    // Update the state for this item
    savedStates[itemId] = isChecked;
    
    // Save back to localStorage
    localStorage.setItem(`checklist-${serviceName}`, JSON.stringify(savedStates));
}

/**
 * Update the UI for a checklist item based on its toggle state
 * @param {string} itemId - The ID of the checklist item
 * @param {boolean} isChecked - Whether the item is checked
 */
function updateItemUI(itemId, isChecked) {
    const toggle = document.getElementById(`toggle-${itemId}`);
    if (!toggle) return;
    
    const listItem = toggle.closest('.list-group-item');
    if (!listItem) return;
    
    if (isChecked) {
        listItem.classList.add('list-group-item-success');
        listItem.querySelector('h5').style.textDecoration = 'line-through';
    } else {
        listItem.classList.remove('list-group-item-success');
        listItem.querySelector('h5').style.textDecoration = 'none';
    }
}