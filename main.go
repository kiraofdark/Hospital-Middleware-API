package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5" // Using jwt v5
	_ "github.com/lib/pq"          // PostgreSQL driver
	"github.com/sirupsen/logrus"   // Import Logrus for structured logging
	"golang.org/x/crypto/bcrypt"

	// Sentry for error tracking (Optional: Uncomment if you want to use Sentry)
	// "github.com/getsentry/sentry-go"

	// Swagger related imports
	_ "hospital-middleware-api/docs" // Import generated docs file - CHANGED TO USE FULL MODULE PATH

	swaggerFiles "github.com/swaggo/files" // swagger embed files
	ginSwagger "github.com/swaggo/gin-swagger"
)

// @title Hospital Middleware API
// @version 1.0
// @description This is a Hospital Middleware API server.
// @host localhost:80
// @BasePath /api

// --- Global Logger Initialization ---
// Initialize Logrus global logger
var log = logrus.New()

func init() {
	log.Out = os.Stdout                       // Output logs to standard output
	log.SetFormatter(&logrus.JSONFormatter{}) // Format logs as JSON for structured logging
	log.SetLevel(logrus.InfoLevel)            // Set default log level

	// Optional: Initialize Sentry SDK for error tracking
	/*
		if err := sentry.Init(sentry.ClientOptions{
			Dsn:         os.Getenv("SENTRY_DSN"), // Get DSN from environment variable
			Environment: os.Getenv("GIN_MODE"),   // Use GIN_MODE as Sentry environment
			Release:     "hospital-middleware-api@1.0.0", // Your application release version
			// Set TracesSampleRate to 1.0 to capture 100% of transactions for performance monitoring.
			// We recommend adjusting this value in production.
			TracesSampleRate: 1.0,
			Debug:           os.Getenv("GIN_MODE") == "debug", // Enable Sentry debug logs in debug mode
		}); err != nil {
			log.Fatalf("Sentry initialization failed: %v", err)
		}
		// Defer a flush to ensure all events are sent before exiting
		// defer sentry.Flush(2 * time.Second)
	*/
}

// --- Models ---

// Patient represents the patient data structure.
// Fields that can be NULL in the database are now standard string for Swagger compatibility.
// Handle null values from DB using sql.NullString during scan, then convert to string.
type Patient struct {
	ID           uint      `json:"id"` // Internal Middleware system ID
	FirstNameTH  string    `json:"first_name_th" db:"first_name_th"`
	MiddleNameTH string    `json:"middle_name_th" db:"middle_name_th"`
	LastNameTH   string    `json:"last_name_th" db:"last_name_th"`
	FirstNameEN  string    `json:"first_name_en" db:"first_name_en"`
	MiddleNameEN string    `json:"middle_name_en" db:"middle_name_en"`
	LastNameEN   string    `json:"last_name_en" db:"last_name_en"`
	DateOfBirth  string    `json:"date_of_birth" db:"date_of_birth"`
	PatientHN    string    `json:"patient_hn" db:"patient_hn"`
	NationalID   string    `json:"national_id" db:"national_id"`
	PassportID   string    `json:"passport_id" db:"passport_id"`
	PhoneNumber  string    `json:"phone_number" db:"phone_number"`
	Email        string    `json:"email" db:"email"`
	Gender       string    `json:"gender" db:"gender"`
	HospitalID   string    `json:"hospital_id" db:"hospital_id"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}

// Staff represents the staff data structure for login and authentication.
type Staff struct {
	ID         uint      `json:"id"`
	Username   string    `json:"username" db:"username"`
	Password   string    `json:"-" db:"password_hash"`         // Hashed password, not exposed in JSON
	HospitalID string    `json:"hospital_id" db:"hospital_id"` // Hospital ID this staff belongs to
	Inactive   bool      `json:"inactive" db:"inactive"`       // Indicates if staff account is inactive
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time `json:"updated_at" db:"updated_at"`
}

// LoginRequest for staff login.
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Hospital string `json:"hospital" binding:"required"` // Hospital ID for login
}

// CreateStaffRequest for creating a new staff member.
type CreateStaffRequest struct {
	Username   string `json:"username" binding:"required"`
	Password   string `json:"password" binding:"required"`
	HospitalID string `json:"hospital_id" binding:"required"`
}

// PatientSearchRequest for searching patients.
// NOTE: This struct is now primarily used for binding query parameters directly.
// Changed to standard string for Swagger compatibility.
type PatientSearchRequest struct {
	NationalID  string `form:"national_id"`
	PassportID  string `form:"passport_id"`
	FirstName   string `form:"first_name"`
	MiddleName  string `form:"middle_name"`
	LastName    string `form:"last_name"`
	DateOfBirth string `form:"date_of_birth"`
	PhoneNumber string `form:"phone_number"`
	Email       string `form:"email"`
}

// Claims represents JWT claims.
type Claims struct {
	StaffID    uint   `json:"staff_id"`
	HospitalID string `json:"hospital_id"`
	jwt.RegisteredClaims
}

// --- Database Configuration and Operations ---

var Db *sql.DB

// InitDB initializes the PostgreSQL database connection.
func InitDB() {
	var err error
	// Construct connection string from environment variables for security
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)

	Db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.WithFields(logrus.Fields{
			"db_host": dbHost,
			"db_name": dbName,
			"error":   err,
		}).Fatalf("Error opening database connection.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = Db.PingContext(ctx)
	if err != nil {
		log.WithFields(logrus.Fields{
			"db_host": dbHost,
			"db_name": dbName,
			"error":   err,
		}).Fatalf("Cannot connect to DB: %v", err)
	}
	log.Info("Connected to the PostgreSQL database successfully!")

	// Set connection pool properties
	Db.SetConnMaxLifetime(time.Minute * 3)
	Db.SetMaxOpenConns(20)
	Db.SetMaxIdleConns(10)

	// Create tables if they don't exist
	createTables()
}

// createTables creates necessary tables in the database.
func createTables() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Staff table schema
	staffTableSQL := `
	CREATE TABLE IF NOT EXISTS staff (
		id SERIAL PRIMARY KEY,
		username VARCHAR(255) UNIQUE NOT NULL,
		password_hash VARCHAR(255) NOT NULL,
		hospital_id VARCHAR(255) NOT NULL,
		inactive BOOLEAN DEFAULT FALSE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`

	// Patient table schema
	// Note: Patient data is assumed to be synced from HIS to this Middleware database
	patientTableSQL := `
	CREATE TABLE IF NOT EXISTS patient (
		id SERIAL PRIMARY KEY,
		first_name_th VARCHAR(255),
		middle_name_th VARCHAR(255),
		last_name_th VARCHAR(255),
		first_name_en VARCHAR(255),
		middle_name_en VARCHAR(255),
		last_name_en VARCHAR(255),
		date_of_birth VARCHAR(10),
		patient_hn VARCHAR(255),
		national_id VARCHAR(255) UNIQUE,
		passport_id VARCHAR(255) UNIQUE,
		phone_number VARCHAR(50),
		email VARCHAR(255),
		gender VARCHAR(1), -- M or F
		hospital_id VARCHAR(255) NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`

	_, err := Db.ExecContext(ctx, staffTableSQL)
	if err != nil {
		log.WithFields(logrus.Fields{
			"table": "staff",
			"error": err,
		}).Fatalf("Error creating staff table.")
	}
	log.Info("Staff table checked/created successfully.")

	_, err = Db.ExecContext(ctx, patientTableSQL)
	if err != nil {
		log.WithFields(logrus.Fields{
			"table": "patient",
			"error": err,
		}).Fatalf("Error creating patient table.")
	}
	log.Info("Patient table checked/created successfully.")

	// Optional: Insert dummy patient data for testing
	// In a real scenario, this data would be populated by an import process.
	insertDummyPatients()
}

// insertDummyPatients inserts sample patient data if the table is empty.
func insertDummyPatients() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check if patients already exist
	var count int
	err := Db.QueryRowContext(ctx, "SELECT COUNT(*) FROM patient").Scan(&count)
	if err != nil {
		log.WithFields(logrus.Fields{
			"table": "patient",
			"error": err,
		}).Warn("Error checking patient count. Proceeding with dummy data insertion.")
		// We still try to insert in case count check failed but table is empty
	}
	if count > 0 {
		log.Info("Dummy patient data already exists. Skipping insertion.")
		return
	}

	// Hospital A patients
	_, err = Db.ExecContext(ctx, `
		INSERT INTO patient (first_name_th, middle_name_th, last_name_th, first_name_en, middle_name_en, last_name_en, date_of_birth, patient_hn, national_id, passport_id, phone_number, gender, hospital_id)
		VALUES
		('สมชาย', NULL, 'ใจดี', 'Somchai', NULL, 'Jaidee', '1980-01-15', 'HA001', '1100000000001', 'PA000000001', '0812345678', 'M', 'HospitalA'),
		('สมหญิง', NULL, 'มีสุข', 'Somyng', NULL, 'Meesook', '1990-05-20', 'HA002', '1100000000002', 'PA000000002', '0898765432', 'F', 'HospitalA');
	`)
	if err != nil {
		log.WithFields(logrus.Fields{
			"hospital_id": "HospitalA",
			"error":       err,
		}).Error("Error inserting dummy HospitalA patients.")
	} else {
		log.Info("Dummy HospitalA patient data inserted.")
	}

	// Hospital B patients (for staff from Hospital B to search)
	_, err = Db.ExecContext(ctx, `
		INSERT INTO patient (first_name_th, middle_name_th, last_name_th, first_name_en, middle_name_en, last_name_en, date_of_birth, patient_hn, national_id, passport_id, phone_number, gender, hospital_id)
		VALUES
		('พงษ์ศักดิ์', NULL, 'รักชาติ', 'Pongsak', NULL, 'Rakchart', '1975-11-10', 'HB001', '2200000000001', 'PB000000001', '0911223344', 'M', 'HospitalB'),
		('มาลี', NULL, 'สุขสันต์', 'Malee', NULL, 'Suksant', '1988-03-25', 'HB002', '2200000000002', 'PB000000002', '0922334455', 'F', 'HospitalB');
	`)
	if err != nil {
		log.WithFields(logrus.Fields{
			"hospital_id": "HospitalB",
			"error":       err,
		}).Error("Error inserting dummy HospitalB patients.")
	} else {
		log.Info("Dummy HospitalB patient data inserted.")
	}

	// Hospital C patients (for staff from Hospital C to search - foreign nationals using Passport ID)
	// Note: Thai name fields are empty as they are foreign nationals.
	_, err = Db.ExecContext(ctx, `
		INSERT INTO patient (first_name_th, middle_name_th, last_name_th, first_name_en, middle_name_en, last_name_en, date_of_birth, patient_hn, national_id, passport_id, phone_number, email, gender, hospital_id)
		VALUES
		(NULL, NULL, NULL, 'Oliver', 'J.', 'Smith', '1995-07-01', 'HC001', NULL, 'US987654321', '0987654321', 'oliver.smith@example.com', 'M', 'HospitalC'),
		(NULL, NULL, NULL, 'Sophia', NULL, 'Garcia', '1982-11-12', 'HC002', NULL, 'ES123456789', '0998877665', 'sophia.garcia@example.com', 'F', 'HospitalC'),
		(NULL, NULL, NULL, 'Kenji', NULL, 'Tanaka', '2000-03-03', 'HC003', NULL, 'JP112233445', '0977665544', 'kenji.tanaka@example.com', 'M', 'HospitalC');
	`)
	if err != nil {
		log.WithFields(logrus.Fields{
			"hospital_id": "HospitalC",
			"error":       err,
		}).Error("Error inserting dummy HospitalC patients.")
	} else {
		log.Info("Dummy HospitalC patient data inserted for HospitalC.")
	}
}

// --- External Hospital API Client (Mock) ---

// HospitalAPatientResponse matches the response structure from Hospital A API.
type HospitalAPatientResponse struct {
	FirstNameTH  string `json:"first_name_th"`
	MiddleNameTH string `json:"middle_name_th"`
	LastNameTH   string `json:"last_name_th"`
	FirstNameEN  string `json:"first_name_en"`
	MiddleNameEN string `json:"middle_name_en"`
	LastNameEN   string `json:"last_name_en"`
	DateOfBirth  string `json:"date_of_birth"`
	PatientHN    string `json:"patient_hn"`
	NationalID   string `json:"national_id"`
	PassportID   string `json:"passport_id"`
	PhoneNumber  string `json:"phone_number"`
	Email        string `json:"email"`
	Gender       string `json:"gender"`
}

// HospitalAClienter defines the interface for interacting with Hospital A's API.
type HospitalAClienter interface {
	SearchPatient(ctx context.Context, idType, idValue string) (*HospitalAPatientResponse, error)
}

// HospitalAClient implements HospitalAClienter for actual HTTP calls.
type HospitalAClient struct {
	BaseURL string
}

// NewHospitalAClient creates a new HospitalAClient instance.
func NewHospitalAClient(baseURL string) *HospitalAClient {
	return &HospitalAClient{BaseURL: baseURL}
}

// SearchPatient simulates calling Hospital A's API.
func (c *HospitalAClient) SearchPatient(ctx context.Context, idType, idValue string) (*HospitalAPatientResponse, error) {
	// In a real application, this would make an actual HTTP GET request to "https://hospital-a.api.co.th/patient/search/{idValue}"
	// and parse the JSON response.

	// For demonstration, we'll simulate a response based on the ID.
	log.WithFields(logrus.Fields{
		"api_call": "HospitalAClient.SearchPatient",
		"id_type":  idType,
		"id_value": idValue,
	}).Info("Simulating call to Hospital A API.")
	time.Sleep(100 * time.Millisecond) // Simulate network latency

	switch idValue {
	case "1100000000001": // National ID
		return &HospitalAPatientResponse{
			FirstNameTH: "สมชาย",
			LastNameTH:  "สุขใจ",
			FirstNameEN: "Somchai",
			LastNameEN:  "Sukjai",
			DateOfBirth: "1985-07-22",
			NationalID:  "1100000000001",
			PatientHN:   "HA0001",
			Gender:      "M",
		}, nil
	case "PASSPORT001": // Passport ID
		return &HospitalAPatientResponse{
			FirstNameEN: "John",
			LastNameEN:  "Doe",
			DateOfBirth: "1970-01-01",
			PassportID:  "PASSPORT001",
			PatientHN:   "HA0002",
			Gender:      "M",
		}, nil
	default:
		return nil, errors.New("patient not found in Hospital A (mock)")
	}
}

// --- Authentication and Authorization ---

var jwtKey = []byte(os.Getenv("JWT_SECRET_KEY")) // Get JWT Secret from environment variable

// GenerateJWT generates a JWT token for the given staff.
func GenerateJWT(staffID uint, hospitalID string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour) // Token expires in 24 hours
	claims := &Claims{
		StaffID:    staffID,
		HospitalID: hospitalID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		log.WithFields(logrus.Fields{
			"staff_id":    staffID,
			"hospital_id": hospitalID,
			"error":       err,
		}).Error("Failed to sign JWT token.")
		// Optional: sentry.CaptureException(err)
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	return tokenString, nil
}

// AuthMiddleware checks the JWT token from the request header.
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			log.Warn("Authorization header missing in request.")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Remove "Bearer " prefix
		if strings.HasPrefix(tokenString, "Bearer ") {
			tokenString = strings.TrimPrefix(tokenString, "Bearer ")
		} else {
			log.WithField("token_format", "invalid").Warn("Invalid token format in Authorization header.")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
			c.Abort()
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				err := fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				log.WithFields(logrus.Fields{
					"alg":   token.Header["alg"],
					"error": err,
				}).Error("JWT parse error: Unexpected signing method.")
				// Optional: sentry.CaptureException(err)
				return nil, err
			}
			return jwtKey, nil
		})

		if err != nil {
			logFields := logrus.Fields{
				"token_error": err.Error(),
			}
			if errors.Is(err, jwt.ErrTokenExpired) {
				logFields["error_type"] = "token_expired"
				log.WithFields(logFields).Warn("JWT token expired.")
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Token expired"})
				// Optional: sentry.CaptureException(err)
			} else if errors.Is(err, jwt.ErrSignatureInvalid) {
				logFields["error_type"] = "invalid_signature"
				log.WithFields(logFields).Warn("JWT signature invalid.")
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token signature"})
				// Optional: sentry.CaptureException(err)
			} else {
				logFields["error_type"] = "jwt_parse_error"
				log.WithFields(logFields).Error("Invalid token during parsing.")
				c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("Invalid token: %v", err)})
				// Optional: sentry.CaptureException(err)
			}
			c.Abort()
			return
		}

		if !token.Valid {
			log.WithField("token_status", "not_valid").Warn("JWT token is not valid after parsing.")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Store claims in context for later use
		c.Set("staff_id", claims.StaffID)
		c.Set("hospital_id", claims.HospitalID)
		log.WithFields(logrus.Fields{
			"staff_id":    claims.StaffID,
			"hospital_id": claims.HospitalID,
			"path":        c.Request.URL.Path,
		}).Info("Authenticated request.")
		c.Next()
	}
}

// --- Handlers ---

// CreateStaffHandler godoc
// @Summary Create a new staff member
// @Description Create a new staff member account for a hospital.
// @Tags staff
// @Accept json
// @Produce json
// @Param staff body CreateStaffRequest true "Staff creation request"
// @Success 201 {object} map[string]interface{} "Staff created successfully"
// @Failure 400 {object} map[string]string "Bad Request - Invalid input or invalid hospital_id"
// @Failure 409 {object} map[string]string "Conflict - Username already exists"
// @Failure 500 {object} map[string]string "Internal Server Error - Failed to create staff"
// @Router /staff/create [post]
func CreateStaffHandler(c *gin.Context) {
	var req CreateStaffRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Removed sensitive request_body logging
		log.WithFields(logrus.Fields{
			"error": err,
		}).Warn("Bad request for staff creation.")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Define allowed hospital IDs. In a real application, these might come from a configuration or a dedicated 'hospitals' table.
	allowedHospitalIDs := []string{"HospitalA", "HospitalB", "HospitalC"} // Ensure this list includes all IDs used in tests too
	isValidHospital := false
	for _, id := range allowedHospitalIDs {
		if req.HospitalID == id {
			isValidHospital = true
			break
		}
	}

	if !isValidHospital {
		log.WithFields(logrus.Fields{
			"hospital_id": req.HospitalID,
		}).Warn("Attempted to create staff with invalid hospital_id.")
		c.JSON(http.StatusBadRequest, gin.H{"Message": "Input hospital_id worng"})
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.WithFields(logrus.Fields{
			"username":    req.Username,
			"hospital_id": req.HospitalID,
			"error":       err,
		}).Error("Error hashing password for new staff.")
		// Optional: sentry.CaptureException(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create staff"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	// Insert staff into the database
	var staffID uint
	// Note: created_at and updated_at will default to CURRENT_TIMESTAMP
	err = Db.QueryRowContext(ctx,
		`INSERT INTO staff (username, password_hash, hospital_id) VALUES ($1, $2, $3) RETURNING id`,
		req.Username, string(hashedPassword), req.HospitalID,
	).Scan(&staffID)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint \"staff_username_key\"") {
			log.WithFields(logrus.Fields{
				"username":    req.Username,
				"hospital_id": req.HospitalID,
			}).Warn("Attempted to create staff with duplicate username.")
			c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
			return
		}
		log.WithFields(logrus.Fields{
			"username":    req.Username,
			"hospital_id": req.HospitalID,
			"error":       err,
		}).Error("Database error inserting new staff.")
		// Optional: sentry.CaptureException(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create staff"})
		return
	}

	log.WithFields(logrus.Fields{
		"staff_id":    staffID,
		"username":    req.Username,
		"hospital_id": req.HospitalID,
	}).Info("Staff created successfully.")
	c.JSON(http.StatusCreated, gin.H{"message": "Staff created successfully", "id": staffID})
}

// LoginStaffHandler godoc
// @Summary Log in a staff member
// @Description Authenticates a staff member and returns a JWT token.
// @Tags staff
// @Accept json
// @Produce json
// @Param login body LoginRequest true "Staff login request"
// @Success 200 {object} map[string]string "Login successful, returns JWT token"
// @Failure 400 {object} map[string]string "Bad Request - Invalid input"
// @Failure 401 {object} map[string]string "Unauthorized - Invalid credentials or inactive account"
// @Failure 500 {object} map[string]string "Internal Server Error - Failed to generate token"
// @Router /staff/login [post]
func LoginStaffHandler(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Removed sensitive request_body logging
		log.WithFields(logrus.Fields{
			"error": err,
		}).Warn("Bad request for staff login.")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	// Retrieve staff from the database, check if inactive
	var staff Staff
	var passwordHash string
	err := Db.QueryRowContext(ctx,
		`SELECT id, password_hash, hospital_id, inactive FROM staff WHERE username = $1 AND hospital_id = $2`,
		req.Username, req.Hospital,
	).Scan(&staff.ID, &passwordHash, &staff.HospitalID, &staff.Inactive)

	if err == sql.ErrNoRows {
		log.WithFields(logrus.Fields{
			"username": req.Username,
			"hospital": req.Hospital,
		}).Warn("Login attempt with invalid username or hospital ID.")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or hospital ID"})
		return
	}
	if err != nil {
		log.WithFields(logrus.Fields{
			"username": req.Username,
			"hospital": req.Hospital,
			"error":    err,
		}).Error("Database error during staff login query.")
		// Optional: sentry.CaptureException(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error during login"})
		return
	}

	if staff.Inactive {
		log.WithFields(logrus.Fields{
			"username":    req.Username,
			"hospital_id": req.Hospital,
			"staff_id":    staff.ID,
		}).Warn("Login attempt by inactive staff account.")
		c.JSON(http.StatusForbidden, gin.H{"error": "Staff account is inactive"})
		return
	}

	// Compare passwords
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password))
	if err != nil {
		log.WithFields(logrus.Fields{
			"username":    req.Username,
			"hospital_id": req.Hospital,
			"staff_id":    staff.ID,
			"error":       err, // Error indicates password mismatch
		}).Warn("Login attempt with incorrect password.")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Generate JWT token
	tokenString, err := GenerateJWT(staff.ID, staff.HospitalID)
	if err != nil {
		log.WithFields(logrus.Fields{
			"username":    req.Username,
			"hospital_id": req.Hospital,
			"staff_id":    staff.ID,
			"error":       err,
		}).Error("Failed to generate JWT token after successful authentication.")
		// Optional: sentry.CaptureException(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	log.WithFields(logrus.Fields{
		"username":    req.Username,
		"hospital_id": req.Hospital,
		"staff_id":    staff.ID,
	}).Info("Staff logged in successfully.")
	c.JSON(http.StatusOK, gin.H{"message": "Login successful", "token": tokenString})
}

// SearchPatientHandler godoc
// @Security ApiKeyAuth
// @Summary Search for a patient by National ID or Passport ID
// @Description Searches for a single patient in the middleware database by national_id or passport_id, filtered by the staff's hospital.
// @Tags patient
// @Accept json
// @Produce json
// @Param id path string true "National ID or Passport ID of the patient to search for"
// @Success 200 {object} Patient "Matching patient data"
// @Failure 401 {object} map[string]string "Unauthorized - Missing or invalid token"
// @Failure 404 {object} map[string]string "Not Found - Specific ID not found in authorized hospital or invalid ID"
// @Failure 500 {object} map[string]string "Internal Server Error - Failed to search patient"
// @Router /patient/search/{id} [get]
func SearchPatientHandler(c *gin.Context) {
	// Get hospital_id from the authenticated staff member
	hospitalID, exists := c.Get("hospital_id")
	if !exists {
		log.Error("Hospital ID not found in context for authenticated staff. This should not happen.")
		// Optional: sentry.CaptureMessage("Hospital ID missing from context after authentication")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Hospital ID not found in context"})
		return
	}
	staffHospitalID := hospitalID.(string)

	idValue := c.Param("id") // Get the ID from the path parameter

	if idValue == "" {
		log.WithFields(logrus.Fields{
			"hospital_id": staffHospitalID,
		}).Warn("Patient search request received without an ID in path.")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Patient ID is required in the path (e.g., /search/12345)"})
		return
	}

	// Build the SQL query to search by national_id OR passport_id within the staff's hospital
	query := `
		SELECT
			id, first_name_th, middle_name_th, last_name_th,
			first_name_en, middle_name_en, last_name_en,
			date_of_birth, patient_hn, national_id, passport_id,
			phone_number, email, gender, hospital_id,
			created_at, updated_at
		FROM patient
		WHERE hospital_id = $1 AND (national_id = $2 OR passport_id = $2)
		LIMIT 1 -- Expecting at most one result for unique IDs
	`
	args := []interface{}{staffHospitalID, idValue}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	var p Patient
	// Declare sql.NullString for all nullable fields that can be NULL in the database
	var firstNameTH, middleNameTH, lastNameTH, firstNameEN, middleNameEN, lastNameEN, dateOfBirth, patientHN, nationalID, passportID, phoneNumber, email sql.NullString

	err := Db.QueryRowContext(ctx, query, args...).Scan(
		&p.ID,
		&firstNameTH,
		&middleNameTH,
		&lastNameTH,
		&firstNameEN,
		&middleNameEN,
		&lastNameEN,
		&dateOfBirth,
		&patientHN,
		&nationalID,
		&passportID,
		&phoneNumber,
		&email,
		&p.Gender,
		&p.HospitalID,
		&p.CreatedAt,
		&p.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		log.WithFields(logrus.Fields{
			"hospital_id": staffHospitalID,
			"search_id":   idValue,
			"result":      "not_found_in_hospital",
		}).Info("Patient ID not found in authorized hospital.")
		// Modified error message format
		c.JSON(http.StatusNotFound, gin.H{"Message": fmt.Sprintf("Not found ID: %s in %s", idValue, staffHospitalID)})
		return
	} else if err != nil {
		log.WithFields(logrus.Fields{
			"hospital_id":    staffHospitalID,
			"search_id":      idValue,
			"database_query": query, // Careful logging full queries in prod for security
			"error":          err,
		}).Error("Database error during patient search by ID.")
		// Optional: sentry.CaptureException(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to search patient"})
		return
	}

	// Convert sql.NullString to string for the Patient struct returned in JSON
	p.FirstNameTH = firstNameTH.String
	p.MiddleNameTH = middleNameTH.String
	p.LastNameTH = lastNameTH.String
	p.FirstNameEN = firstNameEN.String
	p.MiddleNameEN = middleNameEN.String
	p.LastNameEN = lastNameEN.String
	p.DateOfBirth = dateOfBirth.String
	p.PatientHN = patientHN.String
	p.NationalID = nationalID.String
	p.PassportID = passportID.String
	p.PhoneNumber = phoneNumber.String
	p.Email = email.String

	log.WithFields(logrus.Fields{
		"hospital_id": staffHospitalID,
		"search_id":   idValue,
		"patient_id":  p.ID,
	}).Info("Patient found by ID in authorized hospital.")
	c.JSON(http.StatusOK, p)
}

// GetPatientFromHISHandler godoc
// @Summary Get patient from Hospital A HIS
// @Description Simulates fetching patient data directly from an external Hospital A HIS using National ID or Passport ID.
// @Tags HIS (Mock)
// @Accept json
// @Produce json
// @Param id_type path string true "Type of ID (national_id or passport_id)"
// @Param id_value path string true "Value of the ID to search"
// @Success 200 {object} HospitalAPatientResponse "Patient data from HIS"
// @Failure 400 {object} map[string]string "Bad Request - Invalid ID type"
// @Failure 404 {object} map[string]string "Not Found - Patient not found in HIS"
// @Failure 500 {object} map[string]string "Internal Server Error - Failed to retrieve patient from HIS"
// @Router /his/hospital-a/patient/search/{id_type}/{id_value} [get]
func GetPatientFromHISHandler(hospitalAClient HospitalAClienter) gin.HandlerFunc {
	return func(c *gin.Context) {
		idType := c.Param("id_type") // e.g., "national_id" or "passport_id"
		idValue := c.Param("id_value")

		if idType != "national_id" && idType != "passport_id" {
			log.WithFields(logrus.Fields{
				"id_type_requested":  idType,
				"id_value_requested": idValue,
			}).Warn("Invalid ID type requested for HIS search.")
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID type. Must be 'national_id' or 'passport_id'"})
			return
		}

		ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second) // Longer timeout for external API
		defer cancel()

		patientHIS, err := hospitalAClient.SearchPatient(ctx, idType, idValue)
		if err != nil {
			logFields := logrus.Fields{
				"id_type":  idType,
				"id_value": idValue,
				"error":    err,
			}
			if strings.Contains(err.Error(), "not found") {
				log.WithFields(logFields).Info("Patient not found in HIS (mock) for given ID.")
				c.JSON(http.StatusNotFound, gin.H{"error": "Patient not found in HIS"})
			} else {
				log.WithFields(logFields).Error("Error retrieving patient from HIS (mock).")
				// Optional: sentry.CaptureException(err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve patient from HIS"})
			}
			return
		}

		log.WithFields(logrus.Fields{
			"id_type":    idType,
			"id_value":   idValue,
			"patient_hn": patientHIS.PatientHN,
		}).Info("Patient data successfully retrieved from HIS (mock).")
		c.JSON(http.StatusOK, patientHIS)
	}
}

// CORS Middleware to handle Cross-Origin Resource Sharing.
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// In a production environment, restrict Access-Control-Allow-Origin to specific domains.
		// For example: "http://yourfrontend.com"
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent) // 204 No Content
			return
		}

		c.Next()
	}
}

func main() {
	// Set Gin mode based on environment variable
	ginMode := os.Getenv("GIN_MODE")
	if ginMode == "" {
		ginMode = gin.DebugMode // Default to debug mode
	}
	gin.SetMode(ginMode)

	InitDB()
	defer Db.Close()

	router := gin.Default()

	// Apply CORS Middleware
	router.Use(CORSMiddleware())

	// Initialize the mock Hospital A client
	hospitalAClient := NewHospitalAClient("https://hospital-a.api.co.th") // BaseURL is not used by the mock client

	// Public routes
	public := router.Group("/api")
	{
		public.POST("/staff/create", CreateStaffHandler)
		public.POST("/staff/login", LoginStaffHandler)
		// Health check endpoint
		public.GET("/health", func(c *gin.Context) {
			// Optionally check DB connection here
			if err := Db.PingContext(c.Request.Context()); err != nil {
				log.WithField("error", err).Error("Database health check failed.")
				c.JSON(http.StatusInternalServerError, gin.H{"status": "unhealthy", "database": "disconnected"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"status": "healthy", "database": "connected"})
		})
		public.GET("/his/hospital-a/patient/search/:id_type/:id_value", GetPatientFromHISHandler(hospitalAClient))
	}

	// Authenticated routes
	authorized := router.Group("/api")
	authorized.Use(AuthMiddleware())
	{
		// Changed route from /patient/search?national_id=... to /patient/search/{id}
		authorized.GET("/patient/search/:id", SearchPatientHandler)
		// Add other protected routes here
	}

	// Swagger endpoint
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Start the server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // Default port
	}
	log.Infof("Server starting on :%s", port)
	if err := router.Run(":" + port); err != nil {
		log.WithField("error", err).Fatalf("Server failed to start.")
	}
}
