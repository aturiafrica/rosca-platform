// src/handlers/payout.rs
// Payout endpoint handlers for the ROSCA Platform API

use axum::{http::{StatusCode, HeaderValue}, extract::{State, Path, Query}, Json};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{debug, error, info, instrument};
use chrono::{DateTime, Utc};
use crate::handlers::auth::extract_auth_user;

// Authentication extractor
struct AuthUser { user_id: i32; }

// Endpoint 10: POST /api/v1/roscas/:rosca_id/payouts - Create a payout
#[derive(Deserialize)]
struct CreatePayoutRequest {
    user_id: i32,
    amount: f64,
    cycle_number: i32,
}

#[derive(Serialize)]
struct CreatePayoutResponse {
    payout_id: i32,
    rosca_id: i32,
    user_id: i32,
    amount: f64,
    cycle_number: i32,
    payout_status: String,
    created_at: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
pub async fn create_payout(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path(rosca_id): Path<i32>,
    Json(request): Json<CreatePayoutRequest>,
) -> Result<Json<CreatePayoutResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Creating payout for rosca_id: {} by user_id: {}", rosca_id, auth_user.user_id);
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
        error!("Invalid payout amount: {}", request.amount);
        return Err((StatusCode::BAD_REQUEST, "Payout amount must be positive".to_string()));
    }
    if request.cycle_number < 0 {
        error!("Invalid cycle number: {}", request.cycle_number);
        return Err((StatusCode::BAD_REQUEST, "Cycle number must be non-negative".to_string()));
    }

    // Check if the user is a member of the ROSCA and eligible for payout
    let member_eligibility = sqlx::query!(
        "SELECT can_receive_payout 
         FROM rosca_members 
         WHERE rosca_id = $1 AND user_id = $2 AND status = 'active'",
        rosca_id,
        request.user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking member eligibility: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    let can_receive_payout = match member_eligibility {
        Some(m) => m.can_receive_payout,
        None => {
            error!("User {} is not an active member of rosca_id: {}", request.user_id, rosca_id);
            return Err((StatusCode::BAD_REQUEST, "User is not an active member of this ROSCA".to_string()));
        }
    };

    if !can_receive_payout {
        error!("User {} is not eligible for payout in rosca_id: {}", request.user_id, rosca_id);
        return Err((StatusCode::BAD_REQUEST, "Member is not eligible for payout".to_string()));
    }

    // Check ROSCA payout rules
    let payout_rules = sqlx::query_scalar!(
        "SELECT payout_rules->>'auto_disburse' FROM rosca_settings WHERE rosca_id = $1",
        rosca_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error fetching payout rules: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .unwrap_or("false"); // Default to manual disbursement

    let initial_status = if payout_rules == "true" { "completed" } else { "pending" };

    // Create the payout
    let payout = sqlx::query_as!(
        CreatePayoutResponse,
        r#"
        INSERT INTO payouts (rosca_id, user_id, amount, cycle_number, payout_status, payout_at)
        VALUES ($1, $2, $3, $4, $5, CASE WHEN $5 = 'completed' THEN NOW() ELSE NULL END)
        RETURNING payout_id, rosca_id, user_id, amount, cycle_number, payout_status, created_at
        "#,
        rosca_id,
        request.user_id,
        request.amount,
        request.cycle_number,
        initial_status
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error creating payout: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    info!("Payout created: payout_id={} for rosca_id={} with status={}", payout.payout_id, rosca_id, payout.payout_status);
    Ok(Json(payout))
}

// Endpoint 76: GET /api/v1/roscas/:rosca_id/payouts - List payouts
#[derive(Deserialize)]
struct PayoutFilter {
    status: Option<String>,
    cycle_number: Option<i32>,
    limit: Option<i32>,
    offset: Option<i32>,
}

#[derive(Serialize, sqlx::FromRow)]
struct PayoutSummary {
    payout_id: i32,
    rosca_id: i32,
    user_id: i32,
    username: String,
    amount: f64,
    cycle_number: i32,
    payout_status: String,
    payout_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
pub async fn list_payouts(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path(rosca_id): Path<i32>,
    Query(filter): Query<PayoutFilter>,
) -> Result<Json<Vec<PayoutSummary>>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Listing payouts for rosca_id: {} by user_id: {}", rosca_id, auth_user.user_id);
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

    // Apply filters for payouts
    let limit = filter.limit.unwrap_or(50).max(1).min(100);
    let offset = filter.offset.unwrap_or(0).max(0);
    let mut conditions = vec!["p.rosca_id = $1"];
    let mut params: Vec<&(dyn sqlx::Encode<'_, sqlx::Postgres> + sqlx::Type<sqlx::Postgres> + Sync)> = vec![&rosca_id];
    let mut param_index = 2;

    if let Some(ref status) = filter.status {
        conditions.push(format!("p.payout_status = ${}", param_index));
        params.push(status);
        param_index += 1;
    }
    if let Some(cycle_number) = filter.cycle_number {
        conditions.push(format!("p.cycle_number = ${}", param_index));
        params.push(&cycle_number);
        param_index += 1;
    }

    // Fetch payouts with pagination
    let query = format!(
        r#"
        SELECT 
            p.payout_id,
            p.rosca_id,
            p.user_id,
            u.username,
            p.amount,
            p.cycle_number,
            p.payout_status,
            p.payout_at,
            p.created_at
        FROM payouts p
        JOIN users u ON p.user_id = u.user_id
        {}
        ORDER BY p.created_at DESC
        LIMIT ${} OFFSET ${}
        "#,
        if conditions.is_empty() { "WHERE p.rosca_id = $1" } else { format!("WHERE {}", conditions.join(" AND ")) },
        param_index,
        param_index + 1
    );
    params.push(&limit);
    params.push(&offset);

    let payouts = sqlx::query_as_with::<_, PayoutSummary, _>(&query, params)
        .fetch_all(&pool)
        .await
        .map_err(|e| { error!("Database error fetching payouts: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    info!("Retrieved {} payouts for rosca_id: {}", payouts.len(), rosca_id);
    Ok(Json(payouts))
}

// Endpoint 81: PATCH /api/v1/roscas/:rosca_id/payouts/:payout_id - Update payout status
#[derive(Deserialize)]
struct UpdatePayoutRequest {
    payout_status: String,
}

#[derive(Serialize)]
struct UpdatePayoutResponse {
    payout_id: i32,
    rosca_id: i32,
    user_id: i32,
    amount: f64,
    cycle_number: i32,
    payout_status: String,
    payout_at: Option<DateTime<Utc>>,
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
pub async fn update_payout(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path((rosca_id, payout_id)): Path<(i32, i32)>,
    Json(request): Json<UpdatePayoutRequest>,
) -> Result<Json<UpdatePayoutResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Updating payout payout_id: {} in rosca_id: {} by user_id: {}", payout_id, rosca_id, auth_user.user_id);
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

    // Validate payout_status
    let valid_statuses = vec!["pending", "completed", "cancelled"];
    if !valid_statuses.contains(&request.payout_status.as_str()) {
        error!("Invalid payout status: {}", request.payout_status);
        return Err((StatusCode::BAD_REQUEST, "Invalid payout status".to_string()));
    }

    // Check if payout exists and belongs to the ROSCA
    let payout_exists = sqlx::query!(
        "SELECT 1 FROM payouts WHERE payout_id = $1 AND rosca_id = $2",
        payout_id,
        rosca_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking payout: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if !payout_exists {
        error!("Payout payout_id: {} not found in rosca_id: {}", payout_id, rosca_id);
        return Err((StatusCode::NOT_FOUND, "Payout not found in this ROSCA".to_string()));
    }

    // Update payout status
    let payout = sqlx::query_as!(
        UpdatePayoutResponse,
        r#"
        UPDATE payouts
        SET 
            payout_status = $1,
            payout_at = CASE 
                WHEN $1 = 'completed' AND payout_at IS NULL THEN NOW() 
                WHEN $1 IN ('pending', 'cancelled') THEN NULL 
                ELSE payout_at 
            END
        WHERE rosca_id = $2 AND payout_id = $3
        RETURNING payout_id, rosca_id, user_id, amount, cycle_number, payout_status, payout_at
        "#,
        request.payout_status,
        rosca_id,
        payout_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error updating payout: {}", e); (StatusCode::NOT_FOUND, "Payout not found".to_string()) })?;

    info!("Payout updated: payout_id={} in rosca_id={} to status={}", payout_id, rosca_id, payout.payout_status);
    Ok(Json(payout))
}
