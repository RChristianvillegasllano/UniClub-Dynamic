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

const clubsData = [
    {
        id: 1,
        name: "Computer Science Society",
        category: "academic",
        members: 340,
        description: "Advancing technology and programming skills through workshops, hackathons, and networking events.",
        image: "🖥️",
        tags: ["Programming", "Tech", "Innovation"],
        nextEvent: "Hackathon 2024",
        isJoined: true
    },
    {
        id: 2,
        name: "Basketball Warriors",
        category: "sports",
        members: 156,
        description: "University's premier basketball team. Training sessions, tournaments, and team building activities.",
        image: "🏀",
        tags: ["Basketball", "Sports", "Competition"],
        nextEvent: "Inter-University Tournament",
        isJoined: false
    },
    {
        id: 3,
        name: "Drama Club",
        category: "arts",
        members: 89,
        description: "Express yourself through theatrical performances, workshops, and creative storytelling.",
        image: "🎭",
        tags: ["Theater", "Performance", "Creativity"],
        nextEvent: "Romeo & Juliet Production",
        isJoined: true
    },
    {
        id: 4,
        name: "Robotics Engineering",
        category: "tech",
        members: 127,
        description: "Building the future through robotics, AI, and automation projects.",
        image: "🤖",
        tags: ["Robotics", "AI", "Engineering"],
        nextEvent: "Robot Competition",
        isJoined: false
    },
    {
        id: 5,
        name: "Environmental Warriors",
        category: "service",
        members: 203,
        description: "Protecting our planet through sustainability initiatives and community outreach programs.",
        image: "🌱",
        tags: ["Environment", "Sustainability", "Community"],
        nextEvent: "Tree Planting Drive",
        isJoined: true
    },
    {
        id: 6,
        name: "Business Leaders Society",
        category: "academic",
        members: 298,
        description: "Developing future entrepreneurs and business leaders through seminars and networking.",
        image: "💼",
        tags: ["Business", "Leadership", "Networking"],
        nextEvent: "Startup Pitch Competition",
        isJoined: false
    },
    {
        id: 7,
        name: "Photography Club",
        category: "arts",
        members: 167,
        description: "Capturing moments and expressing creativity through the lens of a camera.",
        image: "📸",
        tags: ["Photography", "Visual Arts", "Creativity"],
        nextEvent: "Photo Walk & Workshop",
        isJoined: false
    },
    {
        id: 8,
        name: "Gaming Guild",
        category: "tech",
        members: 445,
        description: "Competitive gaming, tournaments, and building the next generation of esports athletes.",
        image: "🎮",
        tags: ["Gaming", "Esports", "Competition"],
        nextEvent: "LoL Championship",
        isJoined: true
    }
];

const eventsData = [
    {
        id: 1,
        title: "Annual Tech Summit 2024",
        club: "Computer Science Society",
        date: "Dec 15, 2024",
        time: "2:00 PM",
        location: "Main Auditorium",
        attendees: 450,
        image: "🚀"
    },
    {
        id: 2,
        title: "Inter-College Basketball Championship",
        club: "Basketball Warriors",
        date: "Dec 20, 2024",
        time: "10:00 AM",
        location: "Sports Complex",
        attendees: 200,
        image: "🏆"
    },
    {
        id: 3,
        title: "Romeo & Juliet Opening Night",
        club: "Drama Club",
        date: "Jan 10, 2025",
        time: "7:00 PM",
        location: "Theater Hall",
        attendees: 300,
        image: "🎪"
    }
];

// Initialize the application
document.addEventListener('DOMContentLoaded', function () {
    renderClubs(clubsData);
    renderEvents(eventsData);
    initializeFilters();
    initializeSearch();
});

function renderClubs(clubs) {
    const clubsGrid = document.getElementById('clubsGrid');
    clubsGrid.innerHTML = '';

    clubs.forEach(club => {
        const clubCard = createClubCard(club);
        clubsGrid.appendChild(clubCard);
    });
}

function createClubCard(club) {
    const card = document.createElement('div');
    card.className = 'club-card rounded-2xl p-6 shadow-lg hover:shadow-xl transition-all duration-300';

    card.innerHTML = `
                <div class="flex items-start justify-between mb-4">
                    <div class="text-4xl">${club.image}</div>
                    <div class="flex items-center space-x-2">
                        ${club.isJoined ?
            '<span class="bg-green-100 text-green-800 px-3 py-1 rounded-full text-xs font-semibold">Joined</span>' :
            '<button class="bg-primary-500 text-white px-4 py-1 rounded-full text-xs font-semibold hover:bg-primary-600 transition-colors" onclick="joinClub(' + club.id + ')">Join</button>'
        }
                    </div>
                </div>
                
                <h3 class="text-xl font-bold text-gray-900 mb-2">${club.name}</h3>
                <p class="text-gray-600 mb-4 text-sm leading-relaxed">${club.description}</p>
                
                <div class="flex flex-wrap gap-2 mb-4">
                    ${club.tags.map(tag => `<span class="bg-gray-100 text-gray-700 px-2 py-1 rounded-lg text-xs">${tag}</span>`).join('')}
                </div>
                
                <div class="flex items-center justify-between text-sm text-gray-500">
                    <div class="flex items-center">
                        <i class="fas fa-users mr-2"></i>
                        ${club.members} members
                    </div>
                    <div class="flex items-center">
                        <i class="fas fa-calendar mr-2"></i>
                        ${club.nextEvent}
                    </div>
                </div>
            `;

    return card;
}

function renderEvents(events) {
    const eventsGrid = document.getElementById('eventsGrid');
    eventsGrid.innerHTML = '';

    events.forEach(event => {
        const eventCard = createEventCard(event);
        eventsGrid.appendChild(eventCard);
    });
}

function createEventCard(event) {
    const card = document.createElement('div');
    card.className = 'bg-white/10 backdrop-blur-sm rounded-xl p-6 text-white hover:bg-white/20 transition-all';

    card.innerHTML = `
                <div class="flex items-start justify-between mb-4">
                    <div class="text-3xl">${event.image}</div>
                    <span class="bg-white/20 px-3 py-1 rounded-full text-xs font-semibold">${event.date}</span>
                </div>
                
                <h3 class="text-lg font-bold mb-2">${event.title}</h3>
                <p class="text-white/80 text-sm mb-3">by ${event.club}</p>
                
                <div class="space-y-2 text-sm text-white/90">
                    <div class="flex items-center">
                        <i class="fas fa-clock mr-3 w-4"></i>
                        ${event.time}
                    </div>
                    <div class="flex items-center">
                        <i class="fas fa-map-marker-alt mr-3 w-4"></i>
                        ${event.location}
                    </div>
                    <div class="flex items-center">
                        <i class="fas fa-users mr-3 w-4"></i>
                        ${event.attendees} attending
                    </div>
                </div>
                
                <button class="w-full mt-4 bg-white/20 hover:bg-white/30 py-2 rounded-lg font-semibold transition-all">
                    Register for Event
                </button>
            `;

    return card;
}

function initializeFilters() {
    const filterButtons = document.querySelectorAll('.category-filter');

    filterButtons.forEach(button => {
        button.addEventListener('click', function () {
            // Update active state
            filterButtons.forEach(btn => btn.classList.remove('active'));
            this.classList.add('active');

            const category = this.dataset.category;
            filterClubs(category);
        });
    });
}

function filterClubs(category) {
    if (category === 'all') {
        renderClubs(clubsData);
    } else {
        const filteredClubs = clubsData.filter(club => club.category === category);
        renderClubs(filteredClubs);
    }
}

function initializeSearch() {
    const searchInput = document.getElementById('clubSearch');

    searchInput.addEventListener('input', function () {
        const searchTerm = this.value.toLowerCase();
        const filteredClubs = clubsData.filter(club =>
            club.name.toLowerCase().includes(searchTerm) ||
            club.description.toLowerCase().includes(searchTerm) ||
            club.tags.some(tag => tag.toLowerCase().includes(searchTerm))
        );
        renderClubs(filteredClubs);
    });
}

function joinClub(clubId) {
    const club = clubsData.find(c => c.id === clubId);
    if (club) {
        club.isJoined = true;
        club.members += 1;
        renderClubs(clubsData);

        // Show success notification
        showNotification(`Successfully joined ${club.name}! 🎉`, 'success');
    }
}

function showNotification(message, type) {
    const notification = document.createElement('div');
    notification.className = `fixed top-4 right-4 z-50 p-4 rounded-lg shadow-lg transform transition-all duration-300 ${type === 'success' ? 'bg-green-500' : 'bg-blue-500'
        } text-white`;
    notification.innerHTML = message;

    document.body.appendChild(notification);

    // Animate in
    setTimeout(() => notification.classList.add('translate-x-0'), 100);

    // Remove after 3 seconds
    setTimeout(() => {
        notification.classList.add('translate-x-full', 'opacity-0');
        setTimeout(() => document.body.removeChild(notification), 300);
    }, 3000);
}

// Add some interactive animations
document.querySelectorAll('.club-card').forEach(card => {
    card.addEventListener('mouseenter', function () {
        this.style.transform = 'translateY(-8px) scale(1.02)';
    });

    card.addEventListener('mouseleave', function () {
        this.style.transform = 'translateY(0) scale(1)';
    });
});