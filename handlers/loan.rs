// src/handlers/loan.rs
// Loan endpoint handlers for the ROSCA Platform API

use axum::{http::{StatusCode, HeaderValue}, extract::{State, Path, Query}, Json};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{debug, error, info, instrument};
use chrono::{DateTime, Utc};
use crate::handlers::auth::extract_auth_user;

// Authentication extractor
struct AuthUser { user_id: i32; }

// Endpoint 14: GET /api/v1/roscas/:rosca_id/loans - List loans
#[derive(Deserialize)]
struct LoanFilter {
    status: Option<String>,
    limit: Option<i32>,
    offset: Option<i32>,
}

#[derive(Serialize, sqlx::FromRow)]
struct Loan {
    loan_id: i32,
    rosca_name: String,        
    user_id: i32,
    username: String,
    amount: f64,
    interest_rate: f64,
    status: String,
    disbursement_status: String,
    disbursed_at: Option<DateTime<Utc>,
    repayment_cycles: Option<i32>,
    created_at: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
pub async fn list_loans(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path(rosca_id): Path<i32>,
    Query(filter): Query<LoanFilter>,
) -> Result<Json<Vec<Loan>>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Listing loans for rosca_id: {} by user_id: {}", rosca_id, auth_user.user_id);
    tracing::Span::current()
        .record("user_id", &auth_user.user_id)
        .record("rosca_id", &rosca_id);

    // Check if user is an admin member of the ROSCA
    let is_admin_member = sqlx::query_scalar!(
        "SELECT 1 FROM rosca_members WHERE rosca_id = $1 AND user_id = $2 AND member_type = 'admin'",
        rosca_id,
        auth_user.user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking admin membership: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if !is_admin_member {
        let rosca_exists = sqlx::query!("SELECT 1 FROM roscas WHERE rosca_id = $1", rosca_id)
            .fetch_optional(&pool)
            .await
            .map_err(|e| { error!("Database error checking ROSCA existence: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
            .is_some();

        if rosca_exists {
            error!("User {} is not an admin member of rosca_id: {}", auth_user.user_id, rosca_id);
            return Err((StatusCode::FORBIDDEN, "User is not an admin member".to_string()));
        } else {
            error!("ROSCA not found: rosca_id={}", rosca_id);
            return Err((StatusCode::NOT_FOUND, "ROSCA not found".to_string()));
        }
    }

    // Apply filters for loans
    let limit = filter.limit.unwrap_or(50).max(1).min(100);
    let offset = filter.offset.unwrap_or(0).max(0);
    let mut conditions = vec!["l.rosca_id = $1"];
    let mut params: Vec<&(dyn sqlx::Encode<'_, sqlx::Postgres> + sqlx::Type<sqlx::Postgres> + Sync)> = vec![&rosca_id];
    let mut param_index = 2;

    if let Some(ref status) = filter.status {
        conditions.push(format!("l.status = ${}", param_index));
        params.push(status);
        param_index += 1;
    }

    // Fetch loans with pagination, including rosca_name
    let query = format!(
        r#"
        SELECT 
            l.loan_id,
            r.name AS rosca_name,
            l.user_id,
            u.username,
            l.amount,
            l.interest_rate,
            l.status,
            l.disbursement_status,
            l.disbursed_at,
            l.repayment_cycles,
            l.created_at
        FROM loans l
        JOIN users u ON l.user_id = u.user_id
        JOIN roscas r ON l.rosca_id = r.rosca_id
        {}
        ORDER BY l.created_at DESC
        LIMIT ${} OFFSET ${}
        "#,
        if conditions.is_empty() { "WHERE l.rosca_id = $1" } else { format!("WHERE {}", conditions.join(" AND ")) },
        param_index,
        param_index + 1
    );
    params.push(&limit);
    params.push(&offset);

    let loans = sqlx::query_as_with::<_, Loan, _>(&query, params)
        .fetch_all(&pool)
        .await
        .map_err(|e| { error!("Database error fetching loans: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    info!("Retrieved {} loans for rosca_id: {}", loans.len(), rosca_id);
    Ok(Json(loans))
}

// Endpoint 15: POST /api/v1/roscas/:rosca_id/loans - Create a loan
#[derive(Deserialize)]
struct CreateLoanRequest {
    user_id: i32,
    amount: f64,
    interest_rate: f64,
    repayment_cycles: i32,
}

#[derive(Serialize)]
struct CreateLoanResponse {
    loan_id: i32,
    rosca_id: i32,
    user_id: i32,
    amount: f64,
    interest_rate: f64,
    status: String,
    disbursement_status: String,
    created_at: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
pub async fn create_loan(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path(rosca_id): Path<i32>,
    Json(request): Json<CreateLoanRequest>,
) -> Result<Json<CreateLoanResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Creating loan for rosca_id: {} by user_id: {}", rosca_id, auth_user.user_id);
    tracing::Span::current()
        .record("user_id", &auth_user.user_id)
        .record("rosca_id", &rosca_id);

    // Check if user is an admin member of the ROSCA
    let is_admin_member = sqlx::query_scalar!(
        "SELECT 1 FROM rosca_members WHERE rosca_id = $1 AND user_id = $2 AND member_type = 'admin'",
        rosca_id,
        auth_user.user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking admin membership: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if !is_admin_member {
        let rosca_exists = sqlx::query!("SELECT 1 FROM roscas WHERE rosca_id = $1", rosca_id)
            .fetch_optional(&pool)
            .await
            .map_err(|e| { error!("Database error checking ROSCA existence: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
            .is_some();

        if rosca_exists {
            error!("User {} is not an admin member of rosca_id: {}", auth_user.user_id, rosca_id);
            return Err((StatusCode::FORBIDDEN, "User is not an admin member".to_string()));
        } else {
            error!("ROSCA not found: rosca_id={}", rosca_id);
            return Err((StatusCode::NOT_FOUND, "ROSCA not found".to_string()));
        }
    }

    // Validate request data
    if request.amount <= 0.0 {
        error!("Invalid loan amount: {}", request.amount);
        return Err((StatusCode::BAD_REQUEST, "Loan amount must be positive".to_string()));
    }
    if request.interest_rate < 0.0 {
        error!("Invalid interest rate: {}", request.interest_rate);
        return Err((StatusCode::BAD_REQUEST, "Interest rate must be non-negative".to_string()));
    }
    if request.repayment_cycles <= 0 {
        error!("Invalid repayment cycles: {}", request.repayment_cycles);
        return Err((StatusCode::BAD_REQUEST, "Repayment cycles must be positive".to_string()));
    }

    // Check if the user is an active member eligible for a loan
    let member_eligibility = sqlx::query!(
        "SELECT qualifies_for_loan 
         FROM rosca_members 
         WHERE rosca_id = $1 AND user_id = $2 AND status = 'active'",
        rosca_id,
        request.user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking member eligibility: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    let qualifies_for_loan = match member_eligibility {
        Some(m) => m.qualifies_for_loan,
        None => {
            error!("User {} is not an active member of rosca_id: {}", request.user_id, rosca_id);
            return Err((StatusCode::BAD_REQUEST, "User is not an active member of this ROSCA".to_string()));
        }
    };

    if !qualifies_for_loan {
        error!("User {} is not eligible for a loan in rosca_id: {}", request.user_id, rosca_id);
        return Err((StatusCode::BAD_REQUEST, "Member is not eligible for a loan".to_string()));
    }

    // Check loan preferences from rosca_settings
    let loan_prefs = sqlx::query!(
        "SELECT 
            (loan_prefs->>'max_loan_amount')::FLOAT AS max_loan_amount,
            (loan_prefs->>'max_interest_rate')::FLOAT AS max_interest_rate
         FROM rosca_settings 
         WHERE rosca_id = $1",
        rosca_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error fetching loan preferences: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    let (max_loan_amount, max_interest_rate) = match loan_prefs {
        Some(prefs) => (
            prefs.max_loan_amount.unwrap_or(1000.0), // Default max loan amount if not set
            prefs.max_interest_rate.unwrap_or(5.0),  // Default max interest rate if not set
        ),
        None => (1000.0, 5.0), // Defaults if no settings exist
    };

    if request.amount > max_loan_amount {
        error!("Loan amount {} exceeds max_loan_amount: {}", request.amount, max_loan_amount);
        return Err((StatusCode::BAD_REQUEST, format!("Loan amount exceeds maximum allowed: {}", max_loan_amount)));
    }
    if request.interest_rate > max_interest_rate {
        error!("Interest rate {} exceeds max_interest_rate: {}", request.interest_rate, max_interest_rate);
        return Err((StatusCode::BAD_REQUEST, format!("Interest rate exceeds maximum allowed: {}", max_interest_rate)));
    }

    // Create the loan
    let loan = sqlx::query_as!(
        CreateLoanResponse,
        r#"
        INSERT INTO loans (rosca_id, user_id, amount, interest_rate, status, disbursement_status, repayment_cycles)
        VALUES ($1, $2, $3, $4, 'pending', 'pending', $5)
        RETURNING loan_id, rosca_id, user_id, amount, interest_rate, status, disbursement_status, created_at
        "#,
        rosca_id,
        request.user_id,
        request.amount,
        request.interest_rate,
        request.repayment_cycles
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error creating loan: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    info!("Loan created: loan_id={} for rosca_id={} with status={}", loan.loan_id, rosca_id, loan.status);
    Ok(Json(loan))
}

// Endpoint 82: PATCH /api/v1/roscas/:rosca_id/loans/:loan_id - Update loan status
#[derive(Deserialize)]
struct UpdateLoanRequest {
    status: String,
    disbursement_status: Option<String>,
}

#[derive(Serialize)]
struct UpdateLoanResponse {
    loan_id: i32,
    rosca_id: i32,
    user_id: i32,
    amount: f64,
    interest_rate: f64,
    status: String,
    disbursement_status: String,
    disbursed_at: Option<DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
pub async fn update_loan(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path((rosca_id, loan_id)): Path<(i32, i32)>,
    Json(request): Json<UpdateLoanRequest>,
) -> Result<Json<UpdateLoanResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Updating loan loan_id: {} in rosca_id: {} by user_id: {}", loan_id, rosca_id, auth_user.user_id);
    tracing::Span::current()
        .record("user_id", &auth_user.user_id)
        .record("rosca_id", &rosca_id);

    // Check if user is an admin member of the ROSCA
    let is_admin_member = sqlx::query_scalar!(
        "SELECT 1 FROM rosca_members WHERE rosca_id = $1 AND user_id = $2 AND member_type = 'admin'",
        rosca_id,
        auth_user.user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking admin membership: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if !is_admin_member {
        let rosca_exists = sqlx::query!("SELECT 1 FROM roscas WHERE rosca_id = $1", rosca_id)
            .fetch_optional(&pool)
            .await
            .map_err(|e| { error!("Database error checking ROSCA existence: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
            .is_some();

        if rosca_exists {
            error!("User {} is not an admin member of rosca_id: {}", auth_user.user_id, rosca_id);
            return Err((StatusCode::FORBIDDEN, "User is not an admin member".to_string()));
        } else {
            error!("ROSCA not found: rosca_id={}", rosca_id);
            return Err((StatusCode::NOT_FOUND, "ROSCA not found".to_string()));
        }
    }

    // Validate status fields
    let valid_statuses = vec!["pending", "active", "repaid", "defaulted"];
    if !valid_statuses.contains(&request.status.as_str()) {
        error!("Invalid loan status: {}", request.status);
        return Err((StatusCode::BAD_REQUEST, "Invalid loan status".to_string()));
    }

    let disbursement_status = request.disbursement_status.unwrap_or("pending".to_string());
    let valid_disbursement_statuses = vec!["pending", "completed"];
    if !valid_disbursement_statuses.contains(&disbursement_status.as_str()) {
        error!("Invalid disbursement status: {}", disbursement_status);
        return Err((StatusCode::BAD_REQUEST, "Invalid disbursement status".to_string()));
    }

    // Check if loan exists and belongs to the ROSCA
    let loan_exists = sqlx::query!(
        "SELECT 1 FROM loans WHERE loan_id = $1 AND rosca_id = $2",
        loan_id,
        rosca_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking loan: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if !loan_exists {
        error!("Loan loan_id: {} not found in rosca_id: {}", loan_id, rosca_id);
        return Err((StatusCode::NOT_FOUND, "Loan not found in this ROSCA".to_string()));
    }

    // Update loan status and disbursement_status
    let loan = sqlx::query_as!(
        UpdateLoanResponse,
        r#"
        UPDATE loans
        SET 
            status = $1,
            disbursement_status = $2,
            disbursed_at = CASE 
                WHEN $2 = 'completed' AND disbursed_at IS NULL THEN NOW() 
                WHEN $2 = 'pending' THEN NULL 
                ELSE disbursed_at 
            END
        WHERE rosca_id = $3 AND loan_id = $4
        RETURNING loan_id, rosca_id, user_id, amount, interest_rate, status, disbursement_status, disbursed_at
        "#,
        request.status,
        disbursement_status,
        rosca_id,
        loan_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error updating loan: {}", e); (StatusCode::NOT_FOUND, "Loan not found".to_string()) })?;

    info!("Loan updated: loan_id={} in rosca_id={} to status={} disbursement_status={}", 
          loan.loan_id, rosca_id, loan.status, loan.disbursement_status);
    Ok(Json(loan))
}
