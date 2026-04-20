# Build all projects
build:
    cd glasslock && gleam build
    cd glasskey && gleam build
    cd example/backend && gleam build
    cd example/frontend && gleam build

# Test all projects
test:
    cd glasslock && gleam test
    cd glasskey && gleam test

# Format all projects
fmt:
    cd glasslock && gleam format src test
    cd glasskey && gleam format src test
    cd example/backend && gleam format src
    cd example/frontend && gleam format src

# Download all dependencies
deps:
    cd glasslock && gleam deps download
    cd glasskey && gleam deps download
    cd example/backend && gleam deps download
    cd example/frontend && gleam deps download

# Run example backend (port 3000)
example-backend:
    cd example/backend && gleam run

# Run example frontend dev server
example-frontend:
    cd example/frontend && gleam run -m lustre/dev start

# Run both example projects in parallel
[parallel]
example: example-backend example-frontend

# Update all dependencies
update-deps:
    cd glasslock && gleam deps update
    cd glasskey && gleam deps update
    cd example/backend && gleam deps update
    cd example/frontend && gleam deps update
