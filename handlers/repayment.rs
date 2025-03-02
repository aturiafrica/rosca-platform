// src/handlers/repayment.rs
// Loan repayment endpoint handlers for the ROSCA Platform API

use axum::{http::{StatusCode, HeaderValue}, extract::{State, Path, Query}, Json};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{debug, error, info, instrument};
use chrono::{DateTime, Utc};
use crate::handlers::auth::extract_auth_user;

// Authentication extractor
struct AuthUser { user_id: i32; }

// Endpoint 16: GET /api/v1/roscas/:rosca_id/loan_repayments - List loan repayments
#[derive(Deserialize)]
struct RepaymentFilter {
    loan_id: Option<i32>,
    limit: Option<i32>,
    offset: Option<i32>,
}

#[derive(Serialize, sqlx::FromRow)]
struct LoanRepayment {
    repayment_id: i32,
    loan_id: i32,
    amount: f64,
    interest_amount: f64,
    updated_at: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
pub async fn list_loan_repayments(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path(rosca_id): Path<i32>,
    Query(filter): Query<RepaymentFilter>,
) -> Result<Json<Vec<LoanRepayment>>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Listing loan repayments for rosca_id: {} by user_id: {}", rosca_id, auth_user.user_id);
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

    // Apply filters for repayments
    let limit = filter.limit.unwrap_or(50).max(1).min(100);
    let offset = filter.offset.unwrap_or(0).max(0);
    let mut conditions = vec!["l.rosca_id = $1"];
    let mut params: Vec<&(dyn sqlx::Encode<'_, sqlx::Postgres> + sqlx::Type<sqlx::Postgres> + Sync)> = vec![&rosca_id];
    let mut param_index = 2;

    if let Some(loan_id) = filter.loan_id {
        conditions.push(format!("lr.loan_id = ${}", param_index));
        params.push(&loan_id);
        param_index += 1;
    }

    // Fetch loan repayments with pagination
    let query = format!(
        r#"
        SELECT 
            lr.repayment_id,
            lr.loan_id,
            lr.amount,
            lr.interest_amount,
            lr.updated_at
        FROM loan_repayments lr
        JOIN loans l ON lr.loan_id = l.loan_id
        {}
        ORDER BY lr.updated_at DESC
        LIMIT ${} OFFSET ${}
        "#,
        if conditions.is_empty() { "WHERE l.rosca_id = $1" } else { format!("WHERE {}", conditions.join(" AND ")) },
        param_index,
        param_index + 1
    );
    params.push(&limit);
    params.push(&offset);

    let repayments = sqlx::query_as_with::<_, LoanRepayment, _>(&query, params)
        .fetch_all(&pool)
        .await
        .map_err(|e| { error!("Database error fetching loan repayments: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    info!("Retrieved {} loan repayments for rosca_id: {}", repayments.len(), rosca_id);
    Ok(Json(repayments))
}

// Endpoint 17: POST /api/v1/roscas/:rosca_id/loan_repayments - Create a loan repayment
#[derive(Deserialize)]
struct CreateLoanRepaymentRequest {
    loan_id: i32,
    amount: f64,
    interest_amount: f64,
}

#[derive(Serialize)]
struct CreateLoanRepaymentResponse {
    repayment_id: i32,
    loan_id: i32,
    amount: f64,
    interest_amount: f64,
    updated_at: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
pub async fn create_loan_repayment(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path(rosca_id): Path<i32>,
    Json(request): Json<CreateLoanRepaymentRequest>,
) -> Result<Json<CreateLoanRepaymentResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Creating loan repayment for rosca_id: {} by user_id: {}", rosca_id, auth_user.user_id);
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
        error!("Invalid repayment amount: {}", request.amount);
        return Err((StatusCode::BAD_REQUEST, "Repayment amount must be positive".to_string()));
    }
    if request.interest_amount < 0.0 {
        error!("Invalid interest amount: {}", request.interest_amount);
        return Err((StatusCode::BAD_REQUEST, "Interest amount must be non-negative".to_string()));
    }

    // Check if the loan exists and belongs to the ROSCA
    let loan = sqlx::query!(
        r#"
        SELECT user_id, amount, interest_rate, status, disbursement_status 
        FROM loans 
        WHERE loan_id = $1 AND rosca_id = $2
        "#,
        request.loan_id,
        rosca_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking loan: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    let loan = match loan {
        Some(l) => l,
        None => {
            error!("Loan loan_id: {} not found in rosca_id: {}", request.loan_id, rosca_id);
            return Err((StatusCode::NOT_FOUND, "Loan not found in this ROSCA".to_string()));
        }
    };

    // Check loan status and disbursement
    if loan.status != "active" {
        error!("Loan loan_id: {} is not active (status: {})", request.loan_id, loan.status);
        return Err((StatusCode::BAD_REQUEST, "Loan must be active to record repayment".to_string()));
    }
    if loan.disbursement_status != "completed" {
        error!("Loan loan_id: {} is not disbursed (disbursement_status: {})", request.loan_id, loan.disbursement_status);
        return Err((StatusCode::BAD_REQUEST, "Loan must be disbursed to record repayment".to_string()));
    }

    // Create the loan repayment
    let repayment = sqlx::query_as!(
        CreateLoanRepaymentResponse,
        r#"
        INSERT INTO loan_repayments (loan_id, amount, interest_amount)
        VALUES ($1, $2, $3)
        RETURNING repayment_id, loan_id, amount, interest_amount, updated_at
        "#,
        request.loan_id,
        request.amount,
        request.interest_amount
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error creating repayment: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    // Check if loan is fully repaid and update status if necessary
    let total_repaid = sqlx::query_scalar!(
        "SELECT COALESCE(SUM(amount + interest_amount), 0.0) 
         FROM loan_repayments 
         WHERE loan_id = $1",
        request.loan_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error calculating total repaid: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .unwrap_or(0.0);

    let loan_amount_with_interest = loan.amount + (loan.amount * loan.interest_rate / 100.0);
    if total_repaid >= loan_amount_with_interest {
        sqlx::query!(
            "UPDATE loans SET status = 'repaid' WHERE loan_id = $1",
            request.loan_id
        )
        .execute(&pool)
        .await
        .map_err(|e| { error!("Database error updating loan status to repaid: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;
        info!("Loan loan_id: {} marked as repaid due to total repayment: {}", request.loan_id, total_repaid);
    }

    info!("Loan repayment created: repayment_id={} for loan_id={} in rosca_id={}", repayment.repayment_id, request.loan_id, rosca_id);
    Ok(Json(repayment))
}

// Endpoint 83: PATCH /api/v1/roscas/:rosca_id/loan_repayments/:repayment_id - Update loan repayment
#[derive(Deserialize)]
struct UpdateLoanRepaymentRequest {
    amount: Option<f64>,
    interest_amount: Option<f64>,
}

#[derive(Serialize)]
struct UpdateLoanRepaymentResponse {
    repayment_id: i32,
    loan_id: i32,
    amount: f64,
    interest_amount: f64,
    updated_at: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
pub async fn update_loan_repayment(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path((rosca_id, repayment_id)): Path<(i32, i32)>,
    Json(request): Json<UpdateLoanRepaymentRequest>,
) -> Result<Json<UpdateLoanRepaymentResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Updating loan repayment repayment_id: {} in rosca_id: {} by user_id: {}", repayment_id, rosca_id, auth_user.user_id);
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

    // Validate request data if provided
    if let Some(amount) = request.amount {
        if amount <= 0.0 {
            error!("Invalid repayment amount: {}", amount);
            return Err((StatusCode::BAD_REQUEST, "Repayment amount must be positive".to_string()));
        }
    }
    if let Some(interest_amount) = request.interest_amount {
        if interest_amount < 0.0 {
            error!("Invalid interest amount: {}", interest_amount);
            return Err((StatusCode::BAD_REQUEST, "Interest amount must be non-negative".to_string()));
        }
    }

    // Check if repayment exists and belongs to the ROSCA via loan
    let repayment_exists = sqlx::query!(
        "SELECT 1 
         FROM loan_repayments lr 
         JOIN loans l ON lr.loan_id = l.loan_id 
         WHERE lr.repayment_id = $1 AND l.rosca_id = $2",
        repayment_id,
        rosca_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking repayment: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if !repayment_exists {
        error!("Repayment repayment_id: {} not found in rosca_id: {}", repayment_id, rosca_id);
        return Err((StatusCode::NOT_FOUND, "Repayment not found in this ROSCA".to_string()));
    }

    // Update loan repayment
    let repayment = sqlx::query_as!(
        UpdateLoanRepaymentResponse,
        r#"
        UPDATE loan_repayments
        SET 
            amount = COALESCE($1, amount),
            interest_amount = COALESCE($2, interest_amount),
            updated_at = NOW()
        WHERE repayment_id = $3
        RETURNING repayment_id, loan_id, amount, interest_amount, updated_at
        "#,
        request.amount,
        request.interest_amount,
        repayment_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error updating repayment: {}", e); (StatusCode::NOT_FOUND, "Repayment not found".to_string()) })?;

    // Recalculate total repaid and update loan status if fully repaid
    let total_repaid = sqlx::query_scalar!(
        "SELECT COALESCE(SUM(amount + interest_amount), 0.0) 
         FROM loan_repayments 
         WHERE loan_id = $1",
        repayment.loan_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error calculating total repaid: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .unwrap_or(0.0);

    let loan = sqlx::query!(
        "SELECT amount, interest_rate, status 
         FROM loans 
         WHERE loan_id = $1",
        repayment.loan_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error fetching loan: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    let loan_amount_with_interest = loan.amount + (loan.amount * loan.interest_rate / 100.0);
    if total_repaid >= loan_amount_with_interest && loan.status != "repaid" {
        sqlx::query!(
            "UPDATE loans SET status = 'repaid' WHERE loan_id = $1",
            repayment.loan_id
        )
        .execute(&pool)
        .await
        .map_err(|e| { error!("Database error updating loan status to repaid: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;
        info!("Loan loan_id: {} marked as repaid due to total repayment: {}", repayment.loan_id, total_repaid);
    }

    info!("Loan repayment updated: repayment_id={} for loan_id={} in rosca_id={}", repayment_id, repayment.loan_id, rosca_id);
    Ok(Json(repayment))
}
