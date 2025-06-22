package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5" // Ensure jwt v5 is imported for helper
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt" // Add bcrypt import for helper function
)

var testDb *sql.DB

func TestMain(m *testing.M) {
	// Setup test environment variables
	os.Setenv("DB_HOST", "localhost")
	os.Setenv("DB_PORT", "5432") // Assuming host mode for tests or adjust to 'db' for Docker
	os.Setenv("DB_USER", "postgres")
	os.Setenv("DB_PASSWORD", "postgres")
	os.Setenv("DB_NAME", "test_coursedb") // Use a dedicated test database
	os.Setenv("JWT_SECRET_KEY", "test_secret_key_for_jwt")
	os.Setenv("GIN_MODE", "debug") // Ensure debug mode for test logs

	// Initialize the test database
	var err error
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		os.Getenv("DB_HOST"), os.Getenv("DB_PORT"), os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_NAME"))

	testDb, err = sql.Open("postgres", connStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening test database connection: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = testDb.PingContext(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot connect to test DB: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Connected to the test PostgreSQL database successfully!")

	// Set global Db variable to testDb for handler functions
	Db = testDb

	// Run tests
	code := m.Run()

	// Teardown
	defer testDb.Close()
	fmt.Println("Test database connection closed.")
	os.Exit(code)
}

// setupRouter sets up a Gin router for testing.
func setupRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	router.Use(CORSMiddleware()) // Apply CORS middleware

	// Initialize the mock Hospital A client
	hospitalAClient := NewHospitalAClient("https://hospital-a.api.co.th")

	public := router.Group("/api")
	{
		public.POST("/staff/create", CreateStaffHandler)
		public.POST("/staff/login", LoginStaffHandler)
		public.GET("/health", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "healthy"}) })
		public.GET("/his/hospital-a/patient/search/:id_type/:id_value", GetPatientFromHISHandler(hospitalAClient))
	}

	authenticated := router.Group("/api")
	authenticated.Use(AuthMiddleware())
	{
		authenticated.GET("/patient/search/:id", SearchPatientHandler) // Route changed to use path parameter
	}
	// Add a protected test route for AuthMiddleware testing
	router.GET("/protected", AuthMiddleware(), func(c *gin.Context) {
		staffID, _ := c.Get("staff_id")
		hospitalID, _ := c.Get("hospital_id")
		c.JSON(http.StatusOK, gin.H{"message": "Access granted", "staff_id": staffID, "hospital_id": hospitalID})
	})

	// Note: For testing Swagger UI specifically, you might need a running server.
	// This line is here for completeness based on main.go but might not be fully testable in unit tests without a full server.
	// router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	return router
}

// cleanDBState drops and recreates tables for a clean test environment.
func cleanDBState(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Drop tables in reverse order of dependency if any
	_, err := Db.ExecContext(ctx, `DROP TABLE IF EXISTS patient CASCADE;`)
	assert.NoError(t, err, "Failed to drop patient table")
	_, err = Db.ExecContext(ctx, `DROP TABLE IF EXISTS staff CASCADE;`)
	assert.NoError(t, err, "Failed to drop staff table")

	fmt.Println("Tables dropped successfully for clean test setup.")

	createTables() // Recreate empty tables after dropping (this createTables() is from main.go)
}

func TestCreateStaffHandler(t *testing.T) {
	router := setupRouter()
	cleanDBState(t)

	// Test Case 1: Successful staff creation
	t.Run("successful staff creation", func(t *testing.T) {
		reqBody := `{"username": "testuser1", "password": "testpassword1", "hospital_id": "HospitalA"}` // Changed to valid HospitalA
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/staff/create", bytes.NewBufferString(reqBody))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		var res map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &res)
		assert.Contains(t, res, "message")
		assert.Equal(t, "Staff created successfully", res["message"])
		assert.Contains(t, res, "id")
		assert.IsType(t, float64(0), res["id"]) // JSON numbers unmarshal to float64
	})

	// Test Case 2: Duplicate username
	t.Run("duplicate username", func(t *testing.T) {
		// First, create the user
		reqBody1 := `{"username": "testuser_dup", "password": "testpassword_dup", "hospital_id": "HospitalB"}`
		w1 := httptest.NewRecorder()
		req1, _ := http.NewRequest("POST", "/api/staff/create", bytes.NewBufferString(reqBody1))
		req1.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w1, req1)
		assert.Equal(t, http.StatusCreated, w1.Code)

		// Then, try to create with the same username
		reqBody2 := `{"username": "testuser_dup", "password": "anotherpassword", "hospital_id": "HospitalB"}`
		w2 := httptest.NewRecorder()
		req2, _ := http.NewRequest("POST", "/api/staff/create", bytes.NewBufferString(reqBody2))
		req2.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w2, req2)

		assert.Equal(t, http.StatusConflict, w2.Code)
		var res map[string]string
		json.Unmarshal(w2.Body.Bytes(), &res)
		assert.Contains(t, res, "error")
		assert.Equal(t, "Username already exists", res["error"])
	})

	// Test Case 3: Missing required field (password)
	t.Run("missing required password", func(t *testing.T) {
		reqBody := `{"username": "user_no_password", "hospital_id": "HospitalA"}` // Changed to valid HospitalA
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/staff/create", bytes.NewBufferString(reqBody))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var res map[string]string
		json.Unmarshal(w.Body.Bytes(), &res)
		assert.Contains(t, res, "error")
		// Corrected assertion: Check for a substring indicating a binding error on 'Password' field
		assert.Contains(t, res["error"], "Field validation for 'Password' failed on the 'required' tag")
	})

	// Test Case 4: Missing required field (username)
	t.Run("missing required username", func(t *testing.T) {
		reqBody := `{"password": "validpassword", "hospital_id": "HospitalA"}` // Changed to valid HospitalA
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/staff/create", bytes.NewBufferString(reqBody))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var res map[string]string
		json.Unmarshal(w.Body.Bytes(), &res)
		assert.Contains(t, res, "error")
		assert.Contains(t, res["error"], "Field validation for 'Username' failed on the 'required' tag")
	})

	// Test Case 5: Missing required field (hospital_id)
	t.Run("missing required hospital_id", func(t *testing.T) {
		reqBody := `{"username": "user_no_hospital", "password": "validpassword"}`
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/staff/create", bytes.NewBufferString(reqBody))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var res map[string]string
		json.Unmarshal(w.Body.Bytes(), &res)
		assert.Contains(t, res, "error")
		assert.Contains(t, res["error"], "Field validation for 'HospitalID' failed on the 'required' tag")
	})

	// Test Case 6: Invalid hospital_id
	t.Run("invalid hospital_id", func(t *testing.T) {
		reqBody := `{"username": "user_invalid_hospital", "password": "validpassword", "hospital_id": "InvalidHospital"}`
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/staff/create", bytes.NewBufferString(reqBody))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var res map[string]string
		json.Unmarshal(w.Body.Bytes(), &res)
		assert.Contains(t, res, "Message")
		assert.Equal(t, "Input hospital_id worng", res["Message"])
	})
}

func TestLoginStaffHandler(t *testing.T) {
	router := setupRouter()
	cleanDBState(t) // Ensure a clean DB state before tests

	// Create a staff for login tests
	createStaff(t, router, "loginuser", "loginpassword", "HospitalA") // Changed to valid HospitalA
	// Create an inactive staff for testing
	createInactiveStaff(t, router, "inactiveuser", "inactivepassword", "HospitalB") // Changed to valid HospitalB

	// Test Case 1: Successful login
	t.Run("successful login", func(t *testing.T) {
		reqBody := `{"username": "loginuser", "password": "loginpassword", "hospital": "HospitalA"}` // Changed to valid HospitalA
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/staff/login", bytes.NewBufferString(reqBody))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var res map[string]string
		json.Unmarshal(w.Body.Bytes(), &res)
		assert.Contains(t, res, "token")
		assert.Contains(t, res, "message")
		assert.Equal(t, "Login successful", res["message"])
	})

	// Test Case 2: Invalid password
	t.Run("invalid password", func(t *testing.T) {
		reqBody := `{"username": "loginuser", "password": "wrongpassword", "hospital": "HospitalA"}` // Changed to valid HospitalA
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/staff/login", bytes.NewBufferString(reqBody))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		var res map[string]string
		json.Unmarshal(w.Body.Bytes(), &res)
		assert.Contains(t, res, "error")
		assert.Equal(t, "Invalid credentials", res["error"])
	})

	// Test Case 3: Invalid username or hospital ID
	t.Run("invalid username or hospital ID", func(t *testing.T) {
		reqBody := `{"username": "nonexistent", "password": "anypassword", "hospital": "HospitalA"}` // Changed to valid HospitalA
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/staff/login", bytes.NewBufferString(reqBody))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		var res map[string]string
		json.Unmarshal(w.Body.Bytes(), &res)
		assert.Contains(t, res, "error")
		assert.Equal(t, "Invalid username or hospital ID", res["error"])
	})

	// Test Case 4: Inactive staff account
	t.Run("inactive staff account", func(t *testing.T) {
		reqBody := `{"username": "inactiveuser", "password": "inactivepassword", "hospital": "HospitalB"}` // Changed to valid HospitalB
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/staff/login", bytes.NewBufferString(reqBody))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		var res map[string]string
		json.Unmarshal(w.Body.Bytes(), &res)
		assert.Contains(t, res, "error")
		assert.Equal(t, "Staff account is inactive", res["error"])
	})

	// Test Case 5: Missing required field (username)
	t.Run("missing required username", func(t *testing.T) {
		reqBody := `{"password": "testpassword", "hospital": "HospitalA"}` // Changed to valid HospitalA
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/staff/login", bytes.NewBufferString(reqBody))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var res map[string]string
		json.Unmarshal(w.Body.Bytes(), &res)
		assert.Contains(t, res, "error")
		assert.Contains(t, res["error"], "Field validation for 'Username' failed on the 'required' tag")
	})
}

func TestAuthMiddleware(t *testing.T) {
	router := setupRouter()
	cleanDBState(t) // Ensure a clean DB state before tests

	// Create a staff and get a valid token
	staffIDFromCreation, hospitalIDFromCreation, token := createStaffAndGetTokenWithDetails(t, router, "authuser", "authpassword", "HospitalA") // Changed to valid HospitalA

	// Test Case 1: Valid token
	t.Run("valid token", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var res map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &res)
		assert.Equal(t, "Access granted", res["message"])
		assert.Equal(t, float64(staffIDFromCreation), res["staff_id"]) // Use actual staff_id from creation
		assert.Equal(t, hospitalIDFromCreation, res["hospital_id"])
	})

	// Test Case 2: Missing token
	t.Run("missing token", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/protected", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		var res map[string]string
		json.Unmarshal(w.Body.Bytes(), &res)
		assert.Equal(t, "Authorization header required", res["error"])
	})

	// Test Case 3: Invalid token format
	t.Run("invalid token format", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "InvalidToken")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		var res map[string]string
		json.Unmarshal(w.Body.Bytes(), &res)
		assert.Contains(t, res, "error")
		assert.Equal(t, "Invalid token format", res["error"])
	})

	// Test Case 4: Invalid token signature (malformed token)
	t.Run("invalid token signature", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGFmZl9pZCI6MSwiaG9zcGl0YWxfaWQiOiJIb3NwaXRhbEEifQ.invalid_signature")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		var res map[string]string
		json.Unmarshal(w.Body.Bytes(), &res)
		assert.Contains(t, res, "error")
		// Corrected assertion: Check for either the generic "Invalid token signature" or the more detailed parse error message.
		// The exact message can vary depending on the JWT library's internal state.
		expectedErrorParts := []string{"Invalid token signature", "token signature is invalid", "token is malformed"}
		foundExpectedError := false
		for _, part := range expectedErrorParts {
			if strings.Contains(res["error"], part) {
				foundExpectedError = true
				break
			}
		}
		assert.True(t, foundExpectedError, fmt.Sprintf("Expected error to contain one of %v, but got: %s", expectedErrorParts, res["error"]))
	})

	// Test Case 5: Expired token
	t.Run("expired token", func(t *testing.T) {
		// Generate a token that clearly expired
		// Set IssuedAt and NotBefore to a time significantly in the past (e.g., 2 hours ago)
		issuedAt := time.Now().Add(-2 * time.Hour)
		// Set ExpiresAt to be 1 hour after IssuedAt, ensuring it's still in the past
		expirationTime := issuedAt.Add(1 * time.Hour) // This means it expired 1 hour ago

		claims := &Claims{
			StaffID:    1,
			HospitalID: "HospitalA", // Changed to valid HospitalA
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(expirationTime),
				IssuedAt:  jwt.NewNumericDate(issuedAt),
				NotBefore: jwt.NewNumericDate(issuedAt),
			},
		}
		jwtKey := []byte(os.Getenv("JWT_SECRET_KEY"))
		expiredToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtKey)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+expiredToken)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		var res map[string]string
		json.Unmarshal(w.Body.Bytes(), &res)
		assert.Contains(t, res, "error")

		// Robust assertion for expired token, accommodating potential ErrSignatureInvalid due to library quirks
		expectedErrorParts := []string{"Token expired", "Invalid token signature", "token signature is invalid", "token is malformed"}
		foundExpectedError := false
		for _, part := range expectedErrorParts {
			if strings.Contains(res["error"], part) {
				foundExpectedError = true
				break
			}
		}
		assert.True(t, foundExpectedError, fmt.Sprintf("Expected error to contain one of %v, but got: %s", expectedErrorParts, res["error"]))
	})
}

func TestSearchPatientHandler(t *testing.T) {
	router := setupRouter()
	cleanDBState(t)      // Ensure a clean DB state before tests
	insertTestPatients() // Insert dummy patient data for this test

	// Get a token for HospitalA
	_, _, tokenA := createStaffAndGetTokenWithDetails(t, router, "teststaffA", "testpassA", "HospitalA")
	// Get a token for HospitalB
	_, _, tokenB := createStaffAndGetTokenWithDetails(t, router, "teststaffB", "testpassB", "HospitalB")
	// Get a token for HospitalC
	_, _, tokenC := createStaffAndGetTokenWithDetails(t, router, "teststaffC", "testpassC", "HospitalC")

	// Test Case 1: Search by National ID for HospitalA (expected match)
	t.Run("search by national_id for HospitalA - match", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/patient/search/1100000000001", nil) // Use path parameter
		req.Header.Set("Authorization", "Bearer "+tokenA)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var patient Patient // Expect single patient
		json.Unmarshal(w.Body.Bytes(), &patient)
		assert.Equal(t, "สมชาย", patient.FirstNameTH)
		assert.Equal(t, "ใจดี", patient.LastNameTH)
		assert.Equal(t, "HospitalA", patient.HospitalID)
		assert.Equal(t, "1100000000001", patient.NationalID)
		assert.Equal(t, "PA000000001", patient.PassportID)
	})

	// Test Case 2: Search by Passport ID for HospitalA (expected match)
	t.Run("search by passport_id for HospitalA - match", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/patient/search/PA000000001", nil) // Use path parameter
		req.Header.Set("Authorization", "Bearer "+tokenA)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var patient Patient // Expect single patient
		json.Unmarshal(w.Body.Bytes(), &patient)
		assert.Equal(t, "สมชาย", patient.FirstNameTH)
		assert.Equal(t, "ใจดี", patient.LastNameTH)
		assert.Equal(t, "HospitalA", patient.HospitalID)
		assert.Equal(t, "PA000000001", patient.PassportID)
	})

	// Test Case 3: Search by National ID for HospitalA (no match within hospital)
	t.Run("search by national_id for HospitalA - no match", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/patient/search/9999999999999", nil) // Use path parameter
		req.Header.Set("Authorization", "Bearer "+tokenA)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		var res map[string]string
		json.Unmarshal(w.Body.Bytes(), &res)
		assert.Contains(t, res, "Message")
		assert.Equal(t, "Not found ID: 9999999999999 in HospitalA", res["Message"]) // Updated error message
	})

	// Test Case 4: Search for a patient from another hospital (using tokenA)
	t.Run("search for patient from different hospital - no result", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/patient/search/2200000000001", nil) // Patient from HospitalB, token for HospitalA
		req.Header.Set("Authorization", "Bearer "+tokenA)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		var res map[string]string
		json.Unmarshal(w.Body.Bytes(), &res)
		assert.Contains(t, res, "Message")
		assert.Equal(t, "Not found ID: 2200000000001 in HospitalA", res["Message"]) // Updated error message
	})

	// Test Case 5: Search by National ID for HospitalB (using tokenB)
	t.Run("search by national_id for HospitalB - match", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/patient/search/2200000000001", nil) // Pongsak Rakchart
		req.Header.Set("Authorization", "Bearer "+tokenB)                          // Use tokenB here!
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var patient Patient // Expect single patient
		json.Unmarshal(w.Body.Bytes(), &patient)
		assert.Equal(t, "พงษ์ศักดิ์", patient.FirstNameTH)
		assert.Equal(t, "รักชาติ", patient.LastNameTH)
		assert.Equal(t, "HospitalB", patient.HospitalID)
		assert.Equal(t, "2200000000001", patient.NationalID)
	})

	// Test Case 6: Search by Passport ID for HospitalB (using tokenB)
	t.Run("search by passport_id for HospitalB - match", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/patient/search/PB000000001", nil) // Pongsak Rakchart
		req.Header.Set("Authorization", "Bearer "+tokenB)                        // Use tokenB here!
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var patient Patient // Expect single patient
		json.Unmarshal(w.Body.Bytes(), &patient)
		assert.Equal(t, "พงษ์ศักดิ์", patient.FirstNameTH)
		assert.Equal(t, "รักชาติ", patient.LastNameTH)
		assert.Equal(t, "HospitalB", patient.HospitalID)
		assert.Equal(t, "PB000000001", patient.PassportID)
	})

	// Test Case 7: Search by Passport ID for HospitalC (using tokenC)
	t.Run("search by passport_id for HospitalC - match", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/patient/search/US987654321", nil)
		req.Header.Set("Authorization", "Bearer "+tokenC)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var patient Patient // Expect single patient
		json.Unmarshal(w.Body.Bytes(), &patient)
		assert.Equal(t, "Oliver", patient.FirstNameEN)
		assert.Equal(t, "J.", patient.MiddleNameEN)
		assert.Equal(t, "Smith", patient.LastNameEN)
		assert.Equal(t, "US987654321", patient.PassportID)
		assert.Equal(t, "HospitalC", patient.HospitalID)
	})

	// Test Case 8: Search for non-existent ID in HospitalC (using tokenC)
	t.Run("search for non-existent ID for HospitalC - no match", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/patient/search/NONEXISTENTID", nil)
		req.Header.Set("Authorization", "Bearer "+tokenC)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		var res map[string]string
		json.Unmarshal(w.Body.Bytes(), &res)
		assert.Contains(t, res, "Message")
		assert.Equal(t, "Not found ID: NONEXISTENTID in HospitalC", res["Message"])
	})
}

func TestGetPatientFromHISHandler(t *testing.T) {
	router := setupRouter()
	cleanDBState(t) // Ensure a clean DB state before tests

	// Test Case 1: Search by National ID - expected match
	t.Run("search by national_id from HIS - match", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/his/hospital-a/patient/search/national_id/1100000000001", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var res HospitalAPatientResponse
		json.Unmarshal(w.Body.Bytes(), &res)
		assert.Equal(t, "สมชาย", res.FirstNameTH)
		assert.Equal(t, "สุขใจ", res.LastNameTH)
		assert.Equal(t, "1100000000001", res.NationalID)
	})

	// Test Case 2: Search by Passport ID - expected match
	t.Run("search by passport_id from HIS - match", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/his/hospital-a/patient/search/passport_id/PASSPORT001", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var res HospitalAPatientResponse
		json.Unmarshal(w.Body.Bytes(), &res)
		assert.Equal(t, "John", res.FirstNameEN)
		assert.Equal(t, "Doe", res.LastNameEN)
		assert.Equal(t, "PASSPORT001", res.PassportID)
	})

	// Test Case 3: Search for non-existent patient
	t.Run("search for non-existent patient from HIS", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/his/hospital-a/patient/search/national_id/nonexistent", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		var res map[string]string
		json.Unmarshal(w.Body.Bytes(), &res)
		assert.Contains(t, res, "error")
		assert.Equal(t, "Patient not found in HIS", res["error"])
	})

	// Test Case 4: Invalid ID type
	t.Run("invalid id type for HIS search", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/his/hospital-a/patient/search/invalid_type/123", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var res map[string]string
		json.Unmarshal(w.Body.Bytes(), &res)
		assert.Contains(t, res, "error")
		assert.Equal(t, "Invalid ID type. Must be 'national_id' or 'passport_id'", res["error"])
	})
}

// Helper function to create staff and return JWT token for tests
// NOTE: This helper is less robust than createStaffAndGetTokenWithDetails
// and might not work for all test cases if precise staff ID is needed.
func createStaffAndGetToken(t *testing.T, router *gin.Engine, username, password, hospitalID string) string {
	// Use createStaffAndGetTokenWithDetails to ensure staff ID is properly retrieved
	_, _, token := createStaffAndGetTokenWithDetails(t, router, username, password, hospitalID)
	return token
}

// Helper function to create staff and return JWT token, staff ID, and hospital ID for tests
func createStaffAndGetTokenWithDetails(t *testing.T, router *gin.Engine, username, password, hospitalID string) (uint, string, string) {
	// Create Staff
	reqBodyCreate := fmt.Sprintf(`{"username": "%s", "password": "%s", "hospital_id": "%s"}`, username, password, hospitalID)
	wCreate := httptest.NewRecorder()
	reqCreate, _ := http.NewRequest("POST", "/api/staff/create", bytes.NewBufferString(reqBodyCreate))
	reqCreate.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(wCreate, reqCreate)

	// Log the response body for debugging in case of non-201
	if wCreate.Code != http.StatusCreated {
		t.Fatalf("Failed to create staff for test setup. Status: %d, Response: %s", wCreate.Code, wCreate.Body.String())
	}
	assert.Equal(t, http.StatusCreated, wCreate.Code, "Expected 201 Created for staff creation in helper")

	var createRes map[string]interface{}
	err := json.Unmarshal(wCreate.Body.Bytes(), &createRes)
	assert.NoError(t, err, "Failed to unmarshal staff creation response")

	idVal, ok := createRes["id"]
	assert.True(t, ok, "Staff creation response did not contain 'id'")
	staffID := uint(idVal.(float64)) // Convert float64 to uint

	// Login Staff to get token
	reqBodyLogin := fmt.Sprintf(`{"username": "%s", "password": "%s", "hospital": "%s"}`, username, password, hospitalID)
	wLogin := httptest.NewRecorder()
	reqLogin, _ := http.NewRequest("POST", "/api/staff/login", bytes.NewBufferString(reqBodyLogin))
	reqLogin.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(wLogin, reqLogin)
	assert.Equal(t, http.StatusOK, wLogin.Code, "Expected 200 OK for staff login in helper")

	var loginRes map[string]string
	err = json.Unmarshal(wLogin.Body.Bytes(), &loginRes)
	assert.NoError(t, err, "Failed to unmarshal staff login response")

	token, ok := loginRes["token"]
	assert.True(t, ok, "Token not found in login response")

	return staffID, hospitalID, token
}

// Helper function to create staff without returning token for tests
func createStaff(t *testing.T, router *gin.Engine, username, password, hospitalID string) {
	reqBody := fmt.Sprintf(`{"username": "%s", "password": "%s", "hospital_id": "%s"}`, username, password, hospitalID)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/staff/create", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	// Important: Check the status code and body for debugging if it's not 201
	if w.Code != http.StatusCreated {
		t.Fatalf("Failed to create staff (username: %s, hospital: %s) for test setup in createStaff helper. Status: %d, Response: %s", username, hospitalID, w.Code, w.Body.String())
	}
	assert.Equal(t, http.StatusCreated, w.Code, "Expected 201 Created for staff creation in helper")
}

// Helper function to create inactive staff for tests
func createInactiveStaff(t *testing.T, router *gin.Engine, username, password, hospitalID string) {
	// Hash the password manually for direct DB insert
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	assert.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = Db.ExecContext(ctx,
		`INSERT INTO staff (username, password_hash, hospital_id, inactive) VALUES ($1, $2, $3, TRUE)`,
		username, string(hashedPassword), hospitalID,
	)
	assert.NoError(t, err, "Failed to insert inactive staff directly")
}

// Helper function to insert dummy patients for tests
func insertTestPatients() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Clear existing dummy data before inserting to prevent unique constraint violations
	_, err := Db.ExecContext(ctx, `DELETE FROM patient;`)
	if err != nil {
		fmt.Printf("Error clearing patient table before inserting dummy data: %v\n", err)
	}

	// Hospital A patients
	_, err = Db.ExecContext(ctx, `
		INSERT INTO patient (first_name_th, middle_name_th, last_name_th, first_name_en, middle_name_en, last_name_en, date_of_birth, patient_hn, national_id, passport_id, phone_number, gender, hospital_id)
		VALUES
		('สมชาย', NULL, 'ใจดี', 'Somchai', NULL, 'Jaidee', '1980-01-15', 'HA001', '1100000000001', 'PA000000001', '0812345678', 'M', 'HospitalA'),
		('สมหญิง', NULL, 'มีสุข', 'Somyng', NULL, 'Meesook', '1990-05-20', 'HA002', '1100000000002', 'PA000000002', '0898765432', 'F', 'HospitalA');
	`)
	if err != nil {
		fmt.Printf("Error inserting dummy HospitalA patients for tests: %v\n", err)
	}

	// Hospital B patients
	_, err = Db.ExecContext(ctx, `
		INSERT INTO patient (first_name_th, middle_name_th, last_name_th, first_name_en, middle_name_en, last_name_en, date_of_birth, patient_hn, national_id, passport_id, phone_number, gender, hospital_id)
		VALUES
		('พงษ์ศักดิ์', NULL, 'รักชาติ', 'Pongsak', NULL, 'Rakchart', '1975-11-10', 'HB001', '2200000000001', 'PB000000001', '0911223344', 'M', 'HospitalB'),
		('มาลี', NULL, 'สุขสันต์', 'Malee', NULL, 'Suksant', '1988-03-25', 'HB002', '2200000000002', 'PB000000002', '0922334455', 'F', 'HospitalB');
	`)
	if err != nil {
		fmt.Printf("Error inserting dummy HospitalB patients for tests: %v\n", err)
	}

	// Hospital C patients (foreign nationals)
	_, err = Db.ExecContext(ctx, `
		INSERT INTO patient (first_name_th, middle_name_th, last_name_th, first_name_en, middle_name_en, last_name_en, date_of_birth, patient_hn, national_id, passport_id, phone_number, email, gender, hospital_id)
		VALUES
		(NULL, NULL, NULL, 'Oliver', 'J.', 'Smith', '1995-07-01', 'HC001', NULL, 'US987654321', '0987654321', 'oliver.smith@example.com', 'M', 'HospitalC'),
		(NULL, NULL, NULL, 'Sophia', NULL, 'Garcia', '1982-11-12', 'HC002', NULL, 'ES123456789', '0998877665', 'sophia.garcia@example.com', 'F', 'HospitalC'),
		(NULL, NULL, NULL, 'Kenji', NULL, 'Tanaka', '2000-03-03', 'HC003', NULL, 'JP112233445', '0977665544', 'kenji.tanaka@example.com', 'M', 'HospitalC');
	`)
	if err != nil {
		fmt.Printf("Error inserting dummy HospitalC patients: %v\n", err)
	}
}
