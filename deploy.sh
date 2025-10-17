#!/bin/bash
set -e

echo "🚀 Starting CloudShield deployment..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is installed and running
check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi

    if ! docker info &> /dev/null; then
        print_error "Docker daemon is not running. Please start Docker first."
        exit 1
    fi

    print_success "Docker is installed and running"
}

# Check if docker-compose is installed
check_docker_compose() {
    if ! command -v docker-compose &> /dev/null; then
        print_error "docker-compose is not installed. Please install docker-compose first."
        exit 1
    fi

    print_success "docker-compose is available"
}

# Create .env file if it doesn't exist
setup_env() {
    if [ ! -f .env ]; then
        print_status "Creating .env file from template..."
        cp .env.example .env
        print_warning "Please edit .env file with your actual configuration values before starting the services"
        print_warning "Especially important: OAuth client IDs and secrets"
    else
        print_success ".env file already exists"
    fi
}

# Build and start services
start_services() {
    print_status "Building Docker images..."
    docker-compose build

    print_status "Starting services..."
    docker-compose up -d

    print_status "Waiting for services to be ready..."
    sleep 10

    # Check if services are running
    print_status "Checking service health..."
    docker-compose ps
}

# Run database migrations
run_migrations() {
    print_status "Running database migrations..."
    docker-compose exec backend python -m alembic upgrade head
}

# Show service URLs
show_urls() {
    print_success "🎉 CloudShield is now running!"
    echo ""
    echo "Services available at:"
    echo "  📱 Frontend:     http://localhost:3000"
    echo "  🔌 Backend API:  http://localhost:8000"
    echo "  📚 API Docs:     http://localhost:8000/docs"
    echo "  🌸 Flower:       http://localhost:5555"
    echo "  🗄️  Database:     localhost:5432"
    echo "  📡 Redis:        localhost:6379"
    echo ""
    echo "To stop all services: docker-compose down"
    echo "To view logs: docker-compose logs -f [service_name]"
    echo "To restart a service: docker-compose restart [service_name]"
}

# Main deployment flow
main() {
    echo "============================================="
    echo "   CloudShield SaaS Security Analyzer"
    echo "============================================="
    echo ""

    check_docker
    check_docker_compose
    setup_env
    
    # Ask user if they want to continue
    read -p "Continue with deployment? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_warning "Deployment cancelled"
        exit 0
    fi

    start_services
    
    # Wait a bit more for database to be fully ready
    sleep 5
    
    # Run migrations (might fail on first run, that's ok)
    run_migrations || print_warning "Migration failed - this is normal on first run"
    
    show_urls
}

# Handle script interruption
trap 'print_error "Deployment interrupted"; exit 1' INT TERM

# Run main function
main "$@"