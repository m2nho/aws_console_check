/**
 * 상세 보기 기능을 위한 JavaScript
 */
document.addEventListener('DOMContentLoaded', function() {
    // 상세 보기 버튼 클릭 이벤트
    const detailButtons = document.querySelectorAll('[data-bs-toggle="collapse"]');
    detailButtons.forEach(button => {
        button.addEventListener('click', function() {
            const target = this.getAttribute('data-bs-target');
            const icon = this.querySelector('i');
            
            if (icon) {
                if (document.querySelector(target).classList.contains('show')) {
                    icon.classList.remove('fa-chevron-up');
                    icon.classList.add('fa-chevron-down');
                } else {
                    icon.classList.remove('fa-chevron-down');
                    icon.classList.add('fa-chevron-up');
                }
            }
        });
    });
    
    // 테이블 정렬 기능
    const tables = document.querySelectorAll('.table-sortable');
    tables.forEach(table => {
        const headers = table.querySelectorAll('th');
        headers.forEach((header, index) => {
            header.addEventListener('click', function() {
                sortTable(table, index);
            });
            header.style.cursor = 'pointer';
            header.title = '클릭하여 정렬';
            
            // 정렬 아이콘 추가
            const icon = document.createElement('i');
            icon.classList.add('fas', 'fa-sort', 'ms-1', 'text-muted');
            icon.style.fontSize = '0.8em';
            header.appendChild(icon);
        });
    });
    
    // 태그 필터링 기능
    const tagBadges = document.querySelectorAll('.tag-badge');
    tagBadges.forEach(badge => {
        badge.addEventListener('click', function() {
            const tagValue = this.textContent.trim();
            filterByTag(tagValue);
        });
        badge.style.cursor = 'pointer';
        badge.title = '클릭하여 이 태그로 필터링';
    });
    
    // 툴팁 초기화 (Bootstrap 5)
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
});

/**
 * 테이블 정렬 함수
 */
function sortTable(table, columnIndex) {
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr:not(.collapse)'));
    const direction = table.getAttribute('data-sort-direction') === 'asc' ? 'desc' : 'asc';
    
    // 정렬 방향 표시 업데이트
    const headers = table.querySelectorAll('th');
    headers.forEach(header => {
        const icon = header.querySelector('i');
        if (icon) {
            icon.classList.remove('fa-sort-up', 'fa-sort-down');
            icon.classList.add('fa-sort');
            icon.classList.add('text-muted');
        }
    });
    
    const currentHeader = headers[columnIndex];
    const currentIcon = currentHeader.querySelector('i');
    if (currentIcon) {
        currentIcon.classList.remove('fa-sort', 'text-muted');
        currentIcon.classList.add(direction === 'asc' ? 'fa-sort-up' : 'fa-sort-down');
        currentIcon.classList.add('text-primary');
    }
    
    // 행 정렬
    rows.sort((a, b) => {
        const aValue = a.querySelectorAll('td')[columnIndex].textContent.trim();
        const bValue = b.querySelectorAll('td')[columnIndex].textContent.trim();
        
        // 숫자 정렬
        if (!isNaN(aValue) && !isNaN(bValue)) {
            return direction === 'asc' 
                ? parseFloat(aValue) - parseFloat(bValue)
                : parseFloat(bValue) - parseFloat(aValue);
        }
        
        // 문자열 정렬
        return direction === 'asc'
            ? aValue.localeCompare(bValue)
            : bValue.localeCompare(aValue);
    });
    
    // 정렬된 행 다시 삽입
    rows.forEach(row => {
        tbody.appendChild(row);
        
        // 상세 행이 있으면 함께 이동
        const id = row.id || '';
        const detailRow = tbody.querySelector(`[data-parent="${id}"]`);
        if (detailRow) {
            tbody.appendChild(detailRow);
        }
    });
    
    // 정렬 방향 저장
    table.setAttribute('data-sort-direction', direction);
}

/**
 * 태그로 필터링하는 함수
 */
function filterByTag(tagValue) {
    const tables = document.querySelectorAll('.table-sortable');
    tables.forEach(table => {
        const rows = table.querySelectorAll('tbody tr:not(.collapse)');
        
        rows.forEach(row => {
            const detailRow = document.querySelector(`#${row.id}-detail`);
            const tagCells = row.querySelectorAll('.tag-badge');
            let hasTag = false;
            
            tagCells.forEach(cell => {
                if (cell.textContent.trim().includes(tagValue)) {
                    hasTag = true;
                }
            });
            
            if (detailRow) {
                const detailTags = detailRow.querySelectorAll('.tag-badge');
                detailTags.forEach(tag => {
                    if (tag.textContent.trim().includes(tagValue)) {
                        hasTag = true;
                    }
                });
            }
            
            if (hasTag) {
                row.style.display = '';
                if (detailRow) detailRow.style.display = '';
            } else {
                row.style.display = 'none';
                if (detailRow) detailRow.style.display = 'none';
            }
        });
    });
    
    // 필터 표시기 추가
    const filterIndicator = document.getElementById('filter-indicator');
    if (!filterIndicator) {
        const indicator = document.createElement('div');
        indicator.id = 'filter-indicator';
        indicator.className = 'alert alert-info alert-dismissible fade show';
        indicator.innerHTML = `
            <strong>필터 적용됨:</strong> "${tagValue}"
            <button type="button" class="btn-close" onclick="clearFilter()"></button>
        `;
        
        const firstTable = document.querySelector('.table-sortable');
        if (firstTable) {
            firstTable.parentNode.insertBefore(indicator, firstTable);
        }
    } else {
        filterIndicator.querySelector('strong').nextSibling.textContent = ` "${tagValue}"`;
    }
}

/**
 * 필터 초기화 함수
 */
function clearFilter() {
    const tables = document.querySelectorAll('.table-sortable');
    tables.forEach(table => {
        const rows = table.querySelectorAll('tbody tr');
        rows.forEach(row => {
            row.style.display = '';
        });
    });
    
    const filterIndicator = document.getElementById('filter-indicator');
    if (filterIndicator) {
        filterIndicator.remove();
    }
}