# Hospital Middleware API Project

This project demonstrates a basic Go backend application development environment using **Docker Compose** to orchestrate various services, including:

- **Nginx** (Reverse Proxy)
- **Golang Service** (with Gin framework)
- **PostgreSQL Database**

---

## 🚀 Features

- **Golang Backend Service**  
  A Go application built with the [Gin Web Framework](https://gin-gonic.com/).

- **PostgreSQL Database**  
  Stores sample data for backend operations.

- **Nginx Reverse Proxy**  
  Forwards HTTP/HTTPS requests to the Golang service.

- **Docker Compose Orchestration**  
  Simplifies the setup and management of all services.

- **Multi-stage Dockerfile**  
  Reduces final image size for efficient deployment.

---

## 📁 Project Structure

```
.
├── main.go                 # Main Golang application file
├── go.mod                  # Go module definition
├── go.sum                  # Module checksums
├── Dockerfile              # Dockerfile for Go application
├── nginx/
│   └── nginx.conf          # Nginx reverse proxy configuration
└── docker-compose.yml      # Docker Compose configuration
```

---

## ✅ Prerequisites

Ensure you have the following tools installed:

- **[Docker Desktop](https://www.docker.com/products/docker-desktop/)**
- **[Go Programming Language](https://golang.org/dl/)** (v1.22 or higher)

---

## 🛠 Setup & Installation

1. **Clone the Repository**

```bash
git clone <YOUR_REPOSITORY_URL>
cd <YOUR_REPOSITORY_NAME>
```

2. **Prepare Go Files**

Create `main.go` and `go.mod` if not already present. Then run:

```bash
go mod tidy
```

3. **Set Up Nginx Directory**

```bash
mkdir nginx
```

4. **Add Configuration Files**

- Place `Dockerfile` and `docker-compose.yml` in root directory.
- Place `nginx.conf` inside the `nginx/` folder.

---

## ▶ How to Run the Project

In the root directory, run:

```bash
docker-compose up --build -d
```

Options explained:

- `up`: Starts defined services
- `--build`: Rebuilds containers if needed
- `-d`: Runs in detached mode (background)

Check the container status with:

```bash
docker-compose ps
```

---

## 🔍 Testing the Application

### 1. Test Golang API (via Nginx)

Open a browser and navigate to:

```
http://localhost/
```

Expected response:

```json
{
  "message": "Hello from Go Application!"
}
```

---

### 2. Test DB URL (via Nginx)

Navigate to:

```
http://localhost/db-test
```

Expected response:

```json
{
  "message": "DB URL check:",
  "db_url": "postgres://user:password@db:5432/mydatabase?sslmode=disable",
  "note": "You need to implement actual DB connection test in a real app."
}
```

---

## 🧹 Stopping the Environment

### Stop & Remove Containers

```bash
docker-compose down
```

### Remove All (Including Volumes)

```bash
docker-compose down --volumes
```

This will delete **PostgreSQL data** as well.

---

## 📌 Notes

- After editing `main.go`, rebuild with:

```bash
docker-compose up --build -d go_app
```

- `postgres_data` volume stores persistent DB data.

- `main.go` currently **does not** connect to the DB. You must implement the actual DB logic.

- Nginx setup is minimal; for production, consider:
  - SSL/TLS setup
  - Static file routing
  - Load balancing (if scaling)

---

## 🧾 License

This project is for educational purposes. Modify as needed for your real-world application.

---

## 📬 Contact

If you have any questions or suggestions, feel free to open an issue or contact the maintainer.
