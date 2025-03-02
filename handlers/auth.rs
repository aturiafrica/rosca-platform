// src/handlers/auth.rs
// Authentication endpoint handlers for the ROSCA Platform API

use axum::{http::{StatusCode, HeaderValue}, extract::{State, Path}, Json};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{debug, error, info, instrument};
use chrono::{DateTime, Utc};

// Placeholder for actual auth logic (e.g., JWT or session management)
struct AuthUser { user_id: i32; }

#[derive(serde::Serialize, serde::Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

// Endpoint: POST /api/v1/auth/login - User login
#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
    user_id: i32,
    username: String,
}

// Authentication extractor
async fn extract_auth_user(header: HeaderValue) -> Result<AuthUser, (StatusCode, String)> {
    let token = header.to_str()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid Authorization header".to_string()))?
        .strip_prefix("Bearer ")
        .ok_or((StatusCode::BAD_REQUEST, "Missing Bearer prefix".to_string()))?
        .to_string();

    // Decode and validate JWT
    let decoding_key = jsonwebtoken::DecodingKey::from_secret("secret".as_ref()); // Replace with config secret in production
    let validation = jsonwebtoken::Validation::default();
    let token_data = jsonwebtoken::decode::<Claims>(&token, &decoding_key, &validation)
        .map_err(|e| { error!("JWT validation failed: {}", e); (StatusCode::UNAUTHORIZED, "Invalid token".to_string()) })?;

    let user_id: i32 = token_data.claims.sub.parse()
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid user ID in token".to_string()))?;

    // Optional: Check if token is blacklisted (e.g., from logout)
    // Uncomment and adjust if a token_blacklist table is implemented
    /*
    let is_blacklisted = sqlx::query_scalar!(
        "SELECT 1 FROM token_blacklist WHERE user_id = $1 AND token = $2 AND expires_at > NOW()",
        user_id,
        token
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking blacklist: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if is_blacklisted {
        error!("Token is blacklisted for user_id: {}", user_id);
        return Err((StatusCode::UNAUTHORIZED, "Token has been invalidated".to_string()));
    }
    */

    Ok(AuthUser { user_id })
}

#[instrument(skip(pool), fields(user_id))]
pub async fn login(
    State(pool): State<PgPool>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    info!("User login attempt with identifier: {}", request.username);

    // Fetch user by username, email, or phone
    let user = sqlx::query!(
        r#"
        SELECT user_id, username, password_hash, email_verified, phone_verified
        FROM users
        WHERE username = $1 OR email = $1 OR phone = $1
        "#,
        request.username
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error fetching user: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    let user = match user {
        Some(u) => u,
        None => {
            error!("User not found for identifier: {}", request.username);
            return Err((StatusCode::UNAUTHORIZED, "Invalid identifier or password".to_string()));
        }
    };

    // Verify password (assuming password_hash is stored as a bcrypt hash)
    let password_matches = bcrypt::verify(&request.password, &user.password_hash)
        .map_err(|e| { error!("Password verification error: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    if !password_matches {
        error!("Password mismatch for user_id: {}", user.user_id);
        return Err((StatusCode::UNAUTHORIZED, "Invalid identifier or password".to_string()));
    }

    // Check email and phone verification
    if !user.email_verified {
        error!("Email not verified for user_id: {}", user.user_id);
        return Err((StatusCode::FORBIDDEN, "Email verification required".to_string()));
    }
    if !user.phone_verified {
        error!("Phone not verified for user_id: {}", user.user_id);
        return Err((StatusCode::FORBIDDEN, "Phone verification required".to_string()));
    }

    // Generate JWT token (simplified; assumes a secret key)
    let claims = Claims {
        sub: user.user_id.to_string(),
        exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize,
    };
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret("secret".as_ref()), // Replace with actual secret in production
    )
    .map_err(|e| { error!("Token generation error: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    info!("User logged in successfully: user_id={}", user.user_id);
    Ok(Json(LoginResponse {
        token,
        user_id: user.user_id,
        username: user.username,
    }))
}

// Claims struct for JWT (move to a separate module in production)
#[derive(serde::Serialize, serde::Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

// Endpoint: POST /api/v1/auth/logout - User logout
#[derive(Serialize)]
struct LogoutResponse {
    message: String,
}

#[instrument(skip(pool), fields(user_id))]
pub async fn logout(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
) -> Result<Json<LogoutResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("User logout attempt for user_id: {}", auth_user.user_id);
    tracing::Span::current().record("user_id", &auth_user.user_id);

    // In a real implementation with JWT, you'd blacklist the token here
    // For simplicity, assume client discards token; no server-side action beyond logging
    // Optional: Add token to a blacklist table if stateful logout is desired
    /*
    sqlx::query!(
        "INSERT INTO token_blacklist (user_id, token, expires_at) VALUES ($1, $2, $3)",
        auth_user.user_id,
        // Extract token from auth_header here
        chrono::Utc::now() + chrono::Duration::hours(24) // Match token expiration
    )
    .execute(&pool)
    .await
    .map_err(|e| { error!("Database error blacklisting token: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;
    */

    info!("User logged out successfully: user_id={}", auth_user.user_id);
    Ok(Json(LogoutResponse {
        message: "Logged out successfully".to_string(),
    }))
}

// Endpoint: POST /api/v1/auth/register - User registration (creates unverified user)
#[derive(Deserialize)]
struct RegisterRequest {
    username: String,
    password: String,
    email: String,
    phone: String,
    first_name: String,
    last_name: String,
}

#[derive(Serialize)]
struct RegisterResponse {
    user_id: i32,
    username: String,
    created_at: DateTime<Utc>,
    message: String, // Indicates verification required
}

#[instrument(skip(pool), fields(user_id))]
pub async fn register(
    State(pool): State<PgPool>,
    Json(request): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, (StatusCode, String)> {
    info!("User registration attempt for username: {}", request.username);

    // Validate request data
    if request.username.trim().is_empty() {
        error!("Username cannot be empty");
        return Err((StatusCode::BAD_REQUEST, "Username cannot be empty".to_string()));
    }
    if request.password.len() < 8 {
        error!("Password too short for username: {}", request.username);
        return Err((StatusCode::BAD_REQUEST, "Password must be at least 8 characters".to_string()));
    }
    if !request.email.contains('@') || request.email.trim().is_empty() {
        error!("Invalid email for username: {}", request.username);
        return Err((StatusCode::BAD_REQUEST, "Invalid email address".to_string()));
    }
    if request.phone.trim().is_empty() || !request.phone.chars().all(|c| c.is_digit(10) || c == '+' || c == '-') {
        error!("Invalid phone number for username: {}", request.username);
        return Err((StatusCode::BAD_REQUEST, "Invalid phone number".to_string()));
    }
    if request.first_name.trim().is_empty() {
        error!("First name cannot be empty for username: {}", request.username);
        return Err((StatusCode::BAD_REQUEST, "First name cannot be empty".to_string()));
    }
    if request.last_name.trim().is_empty() {
        error!("Last name cannot be empty for username: {}", request.username);
        return Err((StatusCode::BAD_REQUEST, "Last name cannot be empty".to_string()));
    }

    // Check for duplicate username, email, or phone
    let duplicate_check = sqlx::query!(
        r#"
        SELECT 1 FROM users 
        WHERE username = $1 OR email = $2 OR phone = $3
        "#,
        request.username,
        request.email,
        request.phone
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking duplicates: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    if duplicate_check.is_some() {
        error!("Duplicate username, email, or phone: {}", request.username);
        return Err((StatusCode::CONFLICT, "Username, email, or phone number already in use".to_string()));
    }

    // Hash the password
    let password_hash = bcrypt::hash(&request.password, bcrypt::DEFAULT_COST)
        .map_err(|e| { error!("Password hashing error: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    // Insert the user with unverified status
    let user = sqlx::query!(
        r#"
        INSERT INTO users (username, password_hash, email, phone, first_name, last_name, email_verified, phone_verified)
        VALUES ($1, $2, $3, $4, $5, $6, false, false)
        RETURNING user_id, username, created_at
        "#,
        request.username,
        password_hash,
        request.email,
        request.phone,
        request.first_name,
        request.last_name
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error creating user: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    // Generate 6-digit codes for email and phone verification
    let email_code = generate_verification_code();
    let phone_code = generate_verification_code();

    // Store verification codes (assumes a verification_codes table: user_id, code_type, code, expires_at)
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(180);
    sqlx::query!(
        r#"
        INSERT INTO verification_codes (user_id, code_type, code, expires_at)
        VALUES ($1, 'email', $2, $3), ($1, 'phone', $4, $3)
        "#,
        user.user_id,
        email_code,
        expires_at,
        phone_code
    )
    .execute(&pool)
    .await
    .map_err(|e| { error!("Database error storing verification codes: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    // Save verification messages in notifications
    sqlx::query!(
        r#"
        INSERT INTO notifications (user_id, notification_type, message, status, created_at)
        VALUES 
            ($1, 'email_verification', $2, 'pending', NOW()),
            ($1, 'phone_verification', $3, 'pending', NOW())
        "#,
        user.user_id,
        format!("Your email verification code is: {}", email_code),
        format!("Your phone verification code is: {}", phone_code)
    )
    .execute(&pool)
    .await
    .map_err(|e| { error!("Database error saving notifications: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    info!("User registered: user_id={} with username='{}', awaiting verification", user.user_id, user.username);
    Ok(Json(RegisterResponse {
        user_id: user.user_id,
        username: user.username,
        created_at: user.created_at,
        message: "Registration successful. Please verify your email and phone.".to_string(),
    }))
}

// Helper function to generate a 6-digit alphanumeric code
fn generate_verification_code() -> String {
    use rand::{distributions::Alphanumeric, Rng};
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(6)
        .map(char::from)
        .collect()
}

// Endpoint: POST /api/v1/auth/email_verify - Send email verification code
#[derive(Deserialize)]
struct EmailVerifyRequest {
    email: String,
}

#[derive(Serialize)]
struct EmailVerifyResponse {
    message: String,
    code: String, // For simplicity in skeleton; in practice, sent via email, not returned
}

#[instrument(skip(pool), fields(user_id))]
pub async fn email_verify(
    State(pool): State<PgPool>,
    Json(request): Json<EmailVerifyRequest>,
) -> Result<Json<EmailVerifyResponse>, (StatusCode, String)> {
    info!("Email verification request for email: {}", request.email);

    // Validate email
    if !request.email.contains('@') || request.email.trim().is_empty() {
        error!("Invalid email: {}", request.email);
        return Err((StatusCode::BAD_REQUEST, "Invalid email address".to_string()));
    }

    // Fetch user by email
    let user = sqlx::query!(
        r#"
        SELECT user_id, email_verified
        FROM users
        WHERE email = $1
        "#,
        request.email
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error fetching user: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    let user = match user {
        Some(u) => u,
        None => {
            error!("User not found for email: {}", request.email);
            return Err((StatusCode::NOT_FOUND, "User not found with this email".to_string()));
        }
    };

    // Check if email is already verified
    if user.email_verified {
        error!("Email already verified for user_id: {}", user.user_id);
        return Err((StatusCode::BAD_REQUEST, "Email is already verified".to_string()));
    }

    // Generate 6-digit alphanumeric code
    let email_code = generate_verification_code();

    // Store verification code with 180-second expiration
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(180);
    sqlx::query!(
        r#"
        INSERT INTO verification_codes (user_id, code_type, code, expires_at)
        VALUES ($1, 'email', $2, $3)
        ON CONFLICT (user_id, code_type) 
        DO UPDATE SET code = $2, expires_at = $3
        "#,
        user.user_id,
        email_code,
        expires_at
    )
    .execute(&pool)
    .await
    .map_err(|e| { error!("Database error storing email verification code: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    // Save verification message in notifications
    sqlx::query!(
        r#"
        INSERT INTO notifications (user_id, notification_type, message, status, created_at)
        VALUES ($1, 'email_verification', $2, 'pending', NOW())
        "#,
        user.user_id,
        format!("Your email verification code is: {}", email_code)
    )
    .execute(&pool)
    .await
    .map_err(|e| { error!("Database error saving email verification notification: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    info!("Email verification code generated for user_id: {}", user.user_id);
    Ok(Json(EmailVerifyResponse {
        message: "Email verification code sent".to_string(),
        code: email_code, // For simplicity; in production, send via email, don't return
    }))
}

// Helper function to generate a 6-digit alphanumeric code (already in file from register)
fn generate_verification_code() -> String {
    use rand::{distributions::Alphanumeric, Rng};
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(6)
        .map(char::from)
        .collect()
}

// Endpoint: POST /api/v1/auth/email_verify/confirm - Confirm email verification code
#[derive(Deserialize)]
struct ConfirmEmailVerifyRequest {
    email: String,
    code: String,
}

#[derive(Serialize)]
struct ConfirmEmailVerifyResponse {
    message: String,
}

#[instrument(skip(pool), fields(user_id))]
pub async fn confirm_email_verify(
    State(pool): State<PgPool>,
    Json(request): Json<ConfirmEmailVerifyRequest>,
) -> Result<Json<ConfirmEmailVerifyResponse>, (StatusCode, String)> {
    info!("Email verification confirmation attempt for email: {}", request.email);

    // Validate request data
    if !request.email.contains('@') || request.email.trim().is_empty() {
        error!("Invalid email: {}", request.email);
        return Err((StatusCode::BAD_REQUEST, "Invalid email address".to_string()));
    }
    if request.code.len() != 6 || !request.code.chars().all(|c| c.is_alphanumeric()) {
        error!("Invalid verification code format: {}", request.code);
        return Err((StatusCode::BAD_REQUEST, "Verification code must be 6 alphanumeric characters".to_string()));
    }

    // Fetch user by email
    let user = sqlx::query!(
        r#"
        SELECT user_id, email_verified
        FROM users
        WHERE email = $1
        "#,
        request.email
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error fetching user: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    let user = match user {
        Some(u) => u,
        None => {
            error!("User not found for email: {}", request.email);
            return Err((StatusCode::NOT_FOUND, "User not found with this email".to_string()));
        }
    };

    // Check if email is already verified
    if user.email_verified {
        error!("Email already verified for user_id: {}", user.user_id);
        return Err((StatusCode::BAD_REQUEST, "Email is already verified".to_string()));
    }

    // Fetch and verify the code
    let verification = sqlx::query!(
        r#"
        SELECT code, expires_at
        FROM verification_codes
        WHERE user_id = $1 AND code_type = 'email'
        "#,
        user.user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error fetching verification code: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    let (stored_code, expires_at) = match verification {
        Some(v) => (v.code, v.expires_at),
        None => {
            error!("No email verification code found for user_id: {}", user.user_id);
            return Err((StatusCode::BAD_REQUEST, "No verification code found".to_string()));
        }
    };

    // Check if code has expired (180 seconds)
    if chrono::Utc::now() > expires_at {
        // Save failure notification
        sqlx::query!(
            r#"
            INSERT INTO notifications (user_id, notification_type, message, status, created_at)
            VALUES ($1, 'email_verification', $2, 'failed', NOW())
            "#,
            user.user_id,
            "Email verification failed: Code expired"
        )
        .execute(&pool)
        .await
        .map_err(|e| { error!("Database error saving failure notification: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

        error!("Email verification code expired for user_id: {}", user.user_id);
        return Err((StatusCode::BAD_REQUEST, "Verification code has expired".to_string()));
    }

    // Verify the code
    if stored_code != request.code {
        // Save failure notification
        sqlx::query!(
            r#"
            INSERT INTO notifications (user_id, notification_type, message, status, created_at)
            VALUES ($1, 'email_verification', $2, 'failed', NOW())
            "#,
            user.user_id,
            "Email verification failed: Invalid code"
        )
        .execute(&pool)
        .await
        .map_err(|e| { error!("Database error saving failure notification: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

        error!("Invalid email verification code for user_id: {}", user.user_id);
        return Err((StatusCode::BAD_REQUEST, "Invalid verification code".to_string()));
    }

    // Update email_verified status
    sqlx::query!(
        r#"
        UPDATE users
        SET email_verified = true
        WHERE user_id = $1
        "#,
        user.user_id
    )
    .execute(&pool)
    .await
    .map_err(|e| { error!("Database error updating email_verified: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    // Delete the used verification code
    sqlx::query!(
        r#"
        DELETE FROM verification_codes
        WHERE user_id = $1 AND code_type = 'email'
        "#,
        user.user_id
    )
    .execute(&pool)
    .await
    .map_err(|e| { error!("Database error deleting verification code: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    // Save success notification
    sqlx::query!(
        r#"
        INSERT INTO notifications (user_id, notification_type, message, status, created_at)
        VALUES ($1, 'email_verification', $2, 'completed', NOW())
        "#,
        user.user_id,
        "Email verification completed successfully"
    )
    .execute(&pool)
    .await
    .map_err(|e| { error!("Database error saving success notification: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    info!("Email verified successfully for user_id: {}", user.user_id);
    Ok(Json(ConfirmEmailVerifyResponse {
        message: "Email verified successfully".to_string(),
    }))
}

// Endpoint: POST /api/v1/auth/phone_verify - Send phone verification code
#[derive(Deserialize)]
struct PhoneVerifyRequest {
    phone: String,
}

#[derive(Serialize)]
struct PhoneVerifyResponse {
    message: String,
    code: String, // For simplicity in skeleton; in practice, sent via SMS, not returned
}

#[instrument(skip(pool), fields(user_id))]
pub async fn phone_verify(
    State(pool): State<PgPool>,
    Json(request): Json<PhoneVerifyRequest>,
) -> Result<Json<PhoneVerifyResponse>, (StatusCode, String)> {
    info!("Phone verification request for phone: {}", request.phone);

    // Validate phone
    if request.phone.trim().is_empty() || !request.phone.chars().all(|c| c.is_digit(10) || c == '+' || c == '-') {
        error!("Invalid phone number: {}", request.phone);
        return Err((StatusCode::BAD_REQUEST, "Invalid phone number".to_string()));
    }

    // Fetch user by phone
    let user = sqlx::query!(
        r#"
        SELECT user_id, phone_verified
        FROM users
        WHERE phone = $1
        "#,
        request.phone
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error fetching user: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    let user = match user {
        Some(u) => u,
        None => {
            error!("User not found for phone: {}", request.phone);
            return Err((StatusCode::NOT_FOUND, "User not found with this phone number".to_string()));
        }
    };

    // Check if phone is already verified
    if user.phone_verified {
        error!("Phone already verified for user_id: {}", user.user_id);
        return Err((StatusCode::BAD_REQUEST, "Phone is already verified".to_string()));
    }

    // Generate 6-digit alphanumeric code
    let phone_code = generate_verification_code();

    // Store verification code with 180-second expiration
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(180);
    sqlx::query!(
        r#"
        INSERT INTO verification_codes (user_id, code_type, code, expires_at)
        VALUES ($1, 'phone', $2, $3)
        ON CONFLICT (user_id, code_type) 
        DO UPDATE SET code = $2, expires_at = $3
        "#,
        user.user_id,
        phone_code,
        expires_at
    )
    .execute(&pool)
    .await
    .map_err(|e| { error!("Database error storing phone verification code: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    // Save verification message in notifications
    sqlx::query!(
        r#"
        INSERT INTO notifications (user_id, notification_type, message, status, created_at)
        VALUES ($1, 'phone_verification', $2, 'pending', NOW())
        "#,
        user.user_id,
        format!("Your phone verification code is: {}", phone_code)
    )
    .execute(&pool)
    .await
    .map_err(|e| { error!("Database error saving phone verification notification: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    info!("Phone verification code generated for user_id: {}", user.user_id);
    Ok(Json(PhoneVerifyResponse {
        message: "Phone verification code sent".to_string(),
        code: phone_code, // For simplicity; in production, send via SMS, don't return
    }))
}

// Helper function to generate a 6-digit alphanumeric code (already in file from register)
fn generate_verification_code() -> String {
    use rand::{distributions::Alphanumeric, Rng};
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(6)
        .map(char::from)
        .collect()
}

// Endpoint: POST /api/v1/auth/phone_verify/confirm - Confirm phone verification code
#[derive(Deserialize)]
struct ConfirmPhoneVerifyRequest {
    phone: String,
    code: String,
}

#[derive(Serialize)]
struct ConfirmPhoneVerifyResponse {
    message: String,
}

#[instrument(skip(pool), fields(user_id))]
pub async fn confirm_phone_verify(
    State(pool): State<PgPool>,
    Json(request): Json<ConfirmPhoneVerifyRequest>,
) -> Result<Json<ConfirmPhoneVerifyResponse>, (StatusCode, String)> {
    info!("Phone verification confirmation attempt for phone: {}", request.phone);

    // Validate request data
    if request.phone.trim().is_empty() || !request.phone.chars().all(|c| c.is_digit(10) || c == '+' || c == '-') {
        error!("Invalid phone number: {}", request.phone);
        return Err((StatusCode::BAD_REQUEST, "Invalid phone number".to_string()));
    }
    if request.code.len() != 6 || !request.code.chars().all(|c| c.is_alphanumeric()) {
        error!("Invalid verification code format: {}", request.code);
        return Err((StatusCode::BAD_REQUEST, "Verification code must be 6 alphanumeric characters".to_string()));
    }

    // Fetch user by phone
    let user = sqlx::query!(
        r#"
        SELECT user_id, phone_verified
        FROM users
        WHERE phone = $1
        "#,
        request.phone
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error fetching user: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    let user = match user {
        Some(u) => u,
        None => {
            error!("User not found for phone: {}", request.phone);
            return Err((StatusCode::NOT_FOUND, "User not found with this phone number".to_string()));
        }
    };

    // Check if phone is already verified
    if user.phone_verified {
        error!("Phone already verified for user_id: {}", user.user_id);
        return Err((StatusCode::BAD_REQUEST, "Phone is already verified".to_string()));
    }

    // Fetch and verify the code
    let verification = sqlx::query!(
        r#"
        SELECT code, expires_at
        FROM verification_codes
        WHERE user_id = $1 AND code_type = 'phone'
        "#,
        user.user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error fetching verification code: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    let (stored_code, expires_at) = match verification {
        Some(v) => (v.code, v.expires_at),
        None => {
            error!("No phone verification code found for user_id: {}", user.user_id);
            return Err((StatusCode::BAD_REQUEST, "No verification code found".to_string()));
        }
    };

    // Check if code has expired (180 seconds)
    if chrono::Utc::now() > expires_at {
        // Save failure notification
        sqlx::query!(
            r#"
            INSERT INTO notifications (user_id, notification_type, message, status, created_at)
            VALUES ($1, 'phone_verification', $2, 'failed', NOW())
            "#,
            user.user_id,
            "Phone verification failed: Code expired"
        )
        .execute(&pool)
        .await
        .map_err(|e| { error!("Database error saving failure notification: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

        error!("Phone verification code expired for user_id: {}", user.user_id);
        return Err((StatusCode::BAD_REQUEST, "Verification code has expired".to_string()));
    }

    // Verify the code
    if stored_code != request.code {
        // Save failure notification
        sqlx::query!(
            r#"
            INSERT INTO notifications (user_id, notification_type, message, status, created_at)
            VALUES ($1, 'phone_verification', $2, 'failed', NOW())
            "#,
            user.user_id,
            "Phone verification failed: Invalid code"
        )
        .execute(&pool)
        .await
        .map_err(|e| { error!("Database error saving failure notification: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

        error!("Invalid phone verification code for user_id: {}", user.user_id);
        return Err((StatusCode::BAD_REQUEST, "Invalid verification code".to_string()));
    }

    // Update phone_verified status
    sqlx::query!(
        r#"
        UPDATE users
        SET phone_verified = true
        WHERE user_id = $1
        "#,
        user.user_id
    )
    .execute(&pool)
    .await
    .map_err(|e| { error!("Database error updating phone_verified: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    // Delete the used verification code
    sqlx::query!(
        r#"
        DELETE FROM verification_codes
        WHERE user_id = $1 AND code_type = 'phone'
        "#,
        user.user_id
    )
    .execute(&pool)
    .await
    .map_err(|e| { error!("Database error deleting verification code: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    // Save success notification
    sqlx::query!(
        r#"
        INSERT INTO notifications (user_id, notification_type, message, status, created_at)
        VALUES ($1, 'phone_verification', $2, 'completed', NOW())
        "#,
        user.user_id,
        "Phone verification completed successfully"
    )
    .execute(&pool)
    .await
    .map_err(|e| { error!("Database error saving success notification: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    info!("Phone verified successfully for user_id: {}", user.user_id);
    Ok(Json(ConfirmPhoneVerifyResponse {
        message: "Phone verified successfully".to_string(),
    }))
}

// Endpoint: POST /api/v1/auth/password_reset - Generate password reset code
#[derive(Deserialize)]
struct PasswordResetRequest {
    email: String,
}

#[derive(Serialize)]
struct PasswordResetResponse {
    message: String,
    code: String, // For simplicity in skeleton; in practice, sent via email, not returned
}

#[instrument(skip(pool), fields(user_id))]
pub async fn password_reset(
    State(pool): State<PgPool>,
    Json(request): Json<PasswordResetRequest>,
) -> Result<Json<PasswordResetResponse>, (StatusCode, String)> {
    info!("Password reset request for email: {}", request.email);

    // Validate email
    if !request.email.contains('@') || request.email.trim().is_empty() {
        error!("Invalid email: {}", request.email);
        return Err((StatusCode::BAD_REQUEST, "Invalid email address".to_string()));
    }

    // Fetch user by email
    let user = sqlx::query!(
        r#"
        SELECT user_id
        FROM users
        WHERE email = $1
        "#,
        request.email
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error fetching user: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    let user = match user {
        Some(u) => u,
        None => {
            error!("User not found for email: {}", request.email);
            return Err((StatusCode::NOT_FOUND, "User not found with this email".to_string()));
        }
    };

    // Generate 6-digit alphanumeric code
    let reset_code = generate_verification_code();

    // Store reset code with 180-second expiration
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(180);
    sqlx::query!(
        r#"
        INSERT INTO verification_codes (user_id, code_type, code, expires_at)
        VALUES ($1, 'password_reset', $2, $3)
        ON CONFLICT (user_id, code_type) 
        DO UPDATE SET code = $2, expires_at = $3
        "#,
        user.user_id,
        reset_code,
        expires_at
    )
    .execute(&pool)
    .await
    .map_err(|e| { error!("Database error storing password reset code: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    // Save reset message in notifications
    sqlx::query!(
        r#"
        INSERT INTO notifications (user_id, notification_type, message, status, created_at)
        VALUES ($1, 'password_reset', $2, 'pending', NOW())
        "#,
        user.user_id,
        format!("Your password reset code is: {}", reset_code)
    )
    .execute(&pool)
    .await
    .map_err(|e| { error!("Database error saving password reset notification: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    info!("Password reset code generated for user_id: {}", user.user_id);
    Ok(Json(PasswordResetResponse {
        message: "Password reset code sent".to_string(),
        code: reset_code, // For simplicity; in production, send via email, don't return
    }))
}

// Helper function to generate a 6-digit alphanumeric code (already in file from register)
fn generate_verification_code() -> String {
    use rand::{distributions::Alphanumeric, Rng};
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(6)
        .map(char::from)
        .collect()
}

// Endpoint: POST /api/v1/auth/password_reset/verify - Verify password reset code
#[derive(Deserialize)]
struct VerifyResetCodeRequest {
    email: String,
    code: String,
    new_password: String,
}

#[derive(Serialize)]
struct VerifyResetCodeResponse {
    message: String,
}

#[instrument(skip(pool), fields(user_id))]
pub async fn verify_reset_code(
    State(pool): State<PgPool>,
    Json(request): Json<VerifyResetCodeRequest>,
) -> Result<Json<VerifyResetCodeResponse>, (StatusCode, String)> {
    info!("Password reset code verification attempt for email: {}", request.email);

    // Validate request data
    if !request.email.contains('@') || request.email.trim().is_empty() {
        error!("Invalid email: {}", request.email);
        return Err((StatusCode::BAD_REQUEST, "Invalid email address".to_string()));
    }
    if request.code.len() != 6 || !request.code.chars().all(|c| c.is_alphanumeric()) {
        error!("Invalid verification code format: {}", request.code);
        return Err((StatusCode::BAD_REQUEST, "Verification code must be 6 alphanumeric characters".to_string()));
    }
    if request.new_password.len() < 8 {
        error!("New password too short for email: {}", request.email);
        return Err((StatusCode::BAD_REQUEST, "New password must be at least 8 characters".to_string()));
    }

    // Fetch user by email
    let user = sqlx::query!(
        r#"
        SELECT user_id
        FROM users
        WHERE email = $1
        "#,
        request.email
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error fetching user: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    let user = match user {
        Some(u) => u,
        None => {
            error!("User not found for email: {}", request.email);
            return Err((StatusCode::NOT_FOUND, "User not found with this email".to_string()));
        }
    };

    // Fetch and verify the code
    let verification = sqlx::query!(
        r#"
        SELECT code, expires_at
        FROM verification_codes
        WHERE user_id = $1 AND code_type = 'password_reset'
        "#,
        user.user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error fetching reset code: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    let (stored_code, expires_at) = match verification {
        Some(v) => (v.code, v.expires_at),
        None => {
            error!("No password reset code found for user_id: {}", user.user_id);
            return Err((StatusCode::BAD_REQUEST, "No password reset code found".to_string()));
        }
    };

    // Check if code has expired (180 seconds)
    if chrono::Utc::now() > expires_at {
        // Save failure notification
        sqlx::query!(
            r#"
            INSERT INTO notifications (user_id, notification_type, message, status, created_at)
            VALUES ($1, 'password_reset', $2, 'failed', NOW())
            "#,
            user.user_id,
            "Password reset failed: Code expired"
        )
        .execute(&pool)
        .await
        .map_err(|e| { error!("Database error saving failure notification: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

        error!("Password reset code expired for user_id: {}", user.user_id);
        return Err((StatusCode::BAD_REQUEST, "Reset code has expired".to_string()));
    }

    // Verify the code
    if stored_code != request.code {
        // Save failure notification
        sqlx::query!(
            r#"
            INSERT INTO notifications (user_id, notification_type, message, status, created_at)
            VALUES ($1, 'password_reset', $2, 'failed', NOW())
            "#,
            user.user_id,
            "Password reset failed: Invalid code"
        )
        .execute(&pool)
        .await
        .map_err(|e| { error!("Database error saving failure notification: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

        error!("Invalid password reset code for user_id: {}", user.user_id);
        return Err((StatusCode::BAD_REQUEST, "Invalid reset code".to_string()));
    }

    // Hash the new password
    let new_password_hash = bcrypt::hash(&request.new_password, bcrypt::DEFAULT_COST)
        .map_err(|e| { error!("Password hashing error: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    // Update user's password
    sqlx::query!(
        r#"
        UPDATE users
        SET password_hash = $1
        WHERE user_id = $2
        "#,
        new_password_hash,
        user.user_id
    )
    .execute(&pool)
    .await
    .map_err(|e| { error!("Database error updating password: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    // Delete the used reset code
    sqlx::query!(
        r#"
        DELETE FROM verification_codes
        WHERE user_id = $1 AND code_type = 'password_reset'
        "#,
        user.user_id
    )
    .execute(&pool)
    .await
    .map_err(|e| { error!("Database error deleting reset code: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    // Save success notification
    sqlx::query!(
        r#"
        INSERT INTO notifications (user_id, notification_type, message, status, created_at)
        VALUES ($1, 'password_reset', $2, 'completed', NOW())
        "#,
        user.user_id,
        "Password reset completed successfully"
    )
    .execute(&pool)
    .await
    .map_err(|e| { error!("Database error saving success notification: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    info!("Password reset successful for user_id: {}", user.user_id);
    Ok(Json(VerifyResetCodeResponse {
        message: "Password reset successful".to_string(),
    }))
}

// Endpoint: GET /api/v1/auth/profile - Get user profile
#[derive(Serialize)]
struct UserProfileResponse {
    user_id: i32,
    username: String,
    email: String,
    phone: String, 
    first_name: String, 
    last_name: String, 
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id))]
pub async fn get_user_profile(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
) -> Result<Json<UserProfileResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Fetching user profile for user_id: {}", auth_user.user_id);
    tracing::Span::current().record("user_id", &auth_user.user_id);

    // Fetch user profile details
    let profile = sqlx::query!(
        r#"
        SELECT username, email, phone, first_name, last_name, created_at, updated_at
        FROM users
        WHERE user_id = $1
        "#,
        auth_user.user_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error fetching user profile: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    info!("User profile retrieved for user_id: {}", auth_user.user_id);
    Ok(Json(UserProfileResponse {
        user_id: auth_user.user_id,
        username: profile.username,
        email: profile.email,
        phone: profile.phone,
        first_name: profile.first_name,
        last_name: profile.last_name,
        created_at: profile.created_at,
        updated_at: profile.updated_at,
    }))
}
