# --- Builder Stage ---
FROM golang:1.24.4-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum first to leverage Docker cache for initial dependencies.
# This layer changes less often.
COPY go.mod go.sum ./

# Copy the entire application source code, including main.go, other .go files,
# and the generated 'docs' folder.
# This step is crucial for 'go mod tidy' to see all imports, including local ones.
COPY . .

# Run go mod tidy to resolve any new or previously unreferenced modules.
# This ensures that go.mod and go.sum within the build context are fully updated.
# It should also correctly resolve the local import "hospital-middleware-api/docs".
RUN go mod tidy

# Vendor dependencies. This command creates a 'vendor' directory containing all
# transitive dependencies. This makes the build more self-contained and
# often resolves module resolution issues, especially with local packages
# or complex dependency graphs within Docker builds.
RUN go mod vendor

# Build the Go application.
# CGO_ENABLED=0 is important for static binaries compatible with Alpine Linux.
# -ldflags "-s -w" reduces the binary size by stripping debug information.
# -mod=vendor forces the Go build process to use modules from the 'vendor' directory.
# FIX: Changed "hospital-middleware/main.go" to "./main.go"
RUN CGO_ENABLED=0 go build -mod=vendor -ldflags "-s -w" -o hospital-middleware ./main.go

# --- Release Stage ---
# Use a minimal Alpine image for the final production image.
FROM alpine:latest

WORKDIR /app

# Copy the built executable from the builder stage.
COPY --from=builder /app/hospital-middleware .
# Explicitly copy the generated 'docs' folder to the final image.
# This folder contains the swagger.json/yaml and docs.go which gin-swagger needs at runtime.
COPY --from=builder /app/docs ./docs

# Expose the port the application listens on.
EXPOSE 8080

# Command to run the application when the container starts.
CMD ["./hospital-middleware"]
