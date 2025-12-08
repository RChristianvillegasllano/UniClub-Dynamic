tailwind.config = {
    theme: {
        extend: {
            fontFamily: {
                'sans': ['Inter', 'system-ui', 'sans-serif']
            },
            colors: {
                'primary': {
                    50: '#fbecec',
                    100: '#f3c8c8',
                    200: '#e89f9f',
                    300: '#db7070',
                    400: '#b73d3d',
                    500: '#8b1c1c', // Rich Maroon Core
                    600: '#731616',
                    700: '#5a1111',
                    800: '#400c0c',
                    900: '#260707'
                },
                'secondary': {
                    50: '#fffbea',
                    100: '#fff3c4',
                    200: '#ffe180',
                    300: '#ffd23f',
                    400: '#fcbf1e',
                    500: '#e6a800', // Modern Gold Core
                    600: '#cc9400',
                    700: '#a37400',
                    800: '#7a5500',
                    900: '#523800'
                },
                'accent': {
                    50: '#fff4ec',
                    100: '#ffd9c2',
                    200: '#ffb98f',
                    300: '#ff934d',
                    400: '#ff751f',
                    500: '#e85c00', // Strong Orange Core
                    600: '#cc5000',
                    700: '#a34100',
                    800: '#7a3200',
                    900: '#4d2000'
                }
            }
        }
    }
}

// Get clubs data from server (passed via window.clubsData)
let clubsData = window.clubsData || [];

// Initialize the application
document.addEventListener('DOMContentLoaded', function () {
    // Map club data to DOM elements for filtering
    const clubsGrid = document.getElementById('clubsGrid');
    if (clubsGrid && clubsData.length > 0) {
        const clubCards = clubsGrid.querySelectorAll('[data-category]');
        clubCards.forEach((card, index) => {
            if (clubsData[index]) {
                clubsData[index].element = card;
            }
        });
    }
    
    initializeFilters();
    initializeSearch();
});

function renderClubs(clubs) {
    const clubsGrid = document.getElementById('clubsGrid');
    if (!clubsGrid) return;
    
    // Hide all clubs first
    const allClubs = clubsGrid.querySelectorAll('[data-category]');
    allClubs.forEach(card => {
        card.style.display = 'none';
    });
    
    // Show filtered clubs
    clubs.forEach(club => {
        if (club.element) {
            club.element.style.display = 'block';
        }
    });
}

function filterClubsByCategory(category) {
    if (category === 'all') {
        const allClubs = document.querySelectorAll('#clubsGrid [data-category]');
        allClubs.forEach(card => {
            card.style.display = 'block';
        });
    } else {
        const filteredClubs = clubsData.filter(club => {
            const clubCategory = club.category || '';
            return clubCategory.toLowerCase().replace(/\s+/g, '-') === category.toLowerCase();
        });
        
        // Hide all first
        const allClubs = document.querySelectorAll('#clubsGrid [data-category]');
        allClubs.forEach(card => {
            card.style.display = 'none';
        });
        
        // Show matching clubs
        filteredClubs.forEach(club => {
            if (club.element) {
                club.element.style.display = 'block';
            }
        });
    }
}

// Events are already rendered server-side, no need to re-render

function initializeFilters() {
    const filterButtons = document.querySelectorAll('.filter-pill');

    filterButtons.forEach(button => {
        button.addEventListener('click', function () {
            // Update active state
            filterButtons.forEach(btn => {
                btn.classList.remove('active');
            });
            this.classList.add('active');

            const category = this.dataset.category;
            filterClubsByCategory(category);
        });
    });
}

function initializeSearch() {
    const searchInput = document.getElementById('clubSearch');
    if (!searchInput) return;

    searchInput.addEventListener('input', function () {
        const searchTerm = this.value.toLowerCase().trim();
        const clubsGrid = document.getElementById('clubsGrid');
        if (!clubsGrid) return;
        
        const allClubs = clubsGrid.querySelectorAll('[data-category]');
        
        if (!searchTerm) {
            // Show all clubs if search is empty
            allClubs.forEach(card => {
                card.style.display = 'block';
            });
            return;
        }
        
        // Filter clubs based on search term
        allClubs.forEach(card => {
            const name = card.querySelector('h3')?.textContent?.toLowerCase() || '';
            const description = card.querySelector('p')?.textContent?.toLowerCase() || '';
            const category = card.querySelector('[class*="badge"]')?.textContent?.toLowerCase() || '';
            const department = Array.from(card.querySelectorAll('span')).find(s => s.textContent.includes('D'))?.textContent?.toLowerCase() || '';
            
            const matches = name.includes(searchTerm) || 
                          description.includes(searchTerm) || 
                          category.includes(searchTerm) ||
                          department.includes(searchTerm);
            
            card.style.display = matches ? 'block' : 'none';
        });
    });
    
    // Handle search button click
    const searchButton = searchInput.nextElementSibling;
    if (searchButton) {
        searchButton.addEventListener('click', function() {
            searchInput.dispatchEvent(new Event('input'));
        });
    }
}

// Interactive animations for club cards
document.addEventListener('DOMContentLoaded', function() {
    setTimeout(() => {
        document.querySelectorAll('#clubsGrid [data-category]').forEach(card => {
            card.addEventListener('mouseenter', function () {
                this.style.transform = 'scale(1.05)';
            });

            card.addEventListener('mouseleave', function () {
                this.style.transform = 'scale(1)';
            });
        });
    }, 100);
});