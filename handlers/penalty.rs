// src/handlers/penalty.rs
// Penalty endpoint handlers for the ROSCA Platform API

use axum::{http::{StatusCode, HeaderValue}, extract::{State, Path, Query}, Json};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{debug, error, info, instrument};
use chrono::{DateTime, Utc};
use crate::handlers::auth::extract_auth_user;

// Authentication extractor
struct AuthUser { user_id: i32; }

// Endpoint 18: GET /api/v1/roscas/:rosca_id/penalties - List penalties
#[derive(Deserialize)]
struct PenaltyFilter {
    status: Option<String>,
    user_id: Option<i32>,
    limit: Option<i32>,
    offset: Option<i32>,
}

#[derive(Serialize, sqlx::FromRow)]
struct Penalty {
    penalty_id: i32,
    rosca_id: i32,
    user_id: i32,
    username: String,
    amount: f64,
    status: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
pub async fn list_penalties(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path(rosca_id): Path<i32>,
    Query(filter): Query<PenaltyFilter>,
) -> Result<Json<Vec<Penalty>>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Listing penalties for rosca_id: {} by user_id: {}", rosca_id, auth_user.user_id);
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

    // Apply filters for penalties
    let limit = filter.limit.unwrap_or(50).max(1).min(100);
    let offset = filter.offset.unwrap_or(0).max(0);
    let mut conditions = vec!["cp.rosca_id = $1"];
    let mut params: Vec<&(dyn sqlx::Encode<'_, sqlx::Postgres> + sqlx::Type<sqlx::Postgres> + Sync)> = vec![&rosca_id];
    let mut param_index = 2;

    if let Some(ref status) = filter.status {
        conditions.push(format!("cp.status = ${}", param_index));
        params.push(status);
        param_index += 1;
    }
    if let Some(user_id) = filter.user_id {
        conditions.push(format!("cp.user_id = ${}", param_index));
        params.push(&user_id);
        param_index += 1;
    }

    // Fetch penalties with pagination
    let query = format!(
        r#"
        SELECT 
            cp.penalty_id,
            cp.rosca_id,
            cp.user_id,
            u.username,
            cp.amount,
            cp.status,
            cp.created_at,
            cp.updated_at
        FROM contribution_penalties cp
        JOIN users u ON cp.user_id = u.user_id
        {}
        ORDER BY cp.created_at DESC
        LIMIT ${} OFFSET ${}
        "#,
        if conditions.is_empty() { "WHERE cp.rosca_id = $1" } else { format!("WHERE {}", conditions.join(" AND ")) },
        param_index,
        param_index + 1
    );
    params.push(&limit);
    params.push(&offset);

    let penalties = sqlx::query_as_with::<_, Penalty, _>(&query, params)
        .fetch_all(&pool)
        .await
        .map_err(|e| { error!("Database error fetching penalties: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    info!("Retrieved {} penalties for rosca_id: {}", penalties.len(), rosca_id);
    Ok(Json(penalties))
}

// Endpoint 19: POST /api/v1/roscas/:rosca_id/penalties - Create a penalty
#[derive(Deserialize)]
struct CreatePenaltyRequest {
    user_id: i32,
    amount: f64,
}

#[derive(Serialize)]
struct CreatePenaltyResponse {
    penalty_id: i32,
    rosca_id: i32,
    user_id: i32,
    amount: f64,
    status: String,
    created_at: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
pub async fn create_penalty(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path(rosca_id): Path<i32>,
    Json(request): Json<CreatePenaltyRequest>,
) -> Result<Json<CreatePenaltyResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Creating penalty for rosca_id: {} by user_id: {}", rosca_id, auth_user.user_id);
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
        error!("Invalid penalty amount: {}", request.amount);
        return Err((StatusCode::BAD_REQUEST, "Penalty amount must be positive".to_string()));
    }

    // Check if the user is an active member of the ROSCA
    let member_status = sqlx::query_scalar!(
        "SELECT status 
         FROM rosca_members 
         WHERE rosca_id = $1 AND user_id = $2",
        rosca_id,
        request.user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking member status: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    let status = match member_status {
        Some(s) if s == "active" => s,
        Some(s) => {
            error!("User {} is not an active member of rosca_id: {} (status: {})", request.user_id, rosca_id, s);
            return Err((StatusCode::BAD_REQUEST, format!("User is not an active member (status: {})", s)));
        }
        None => {
            error!("User {} is not a member of rosca_id: {}", request.user_id, rosca_id);
            return Err((StatusCode::BAD_REQUEST, "User is not a member of this ROSCA".to_string()));
        }
    };

    // Create the penalty
    let penalty = sqlx::query_as!(
        CreatePenaltyResponse,
        r#"
        INSERT INTO contribution_penalties (rosca_id, user_id, amount, status)
        VALUES ($1, $2, $3, 'pending')
        RETURNING penalty_id, rosca_id, user_id, amount, status, created_at
        "#,
        rosca_id,
        request.user_id,
        request.amount
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error creating penalty: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    info!("Penalty created: penalty_id={} for rosca_id={} with status={}", penalty.penalty_id, rosca_id, penalty.status);
    Ok(Json(penalty))
}

// Endpoint 20: PATCH /api/v1/roscas/:rosca_id/penalties/:penalty_id/status - Update penalty status
#[derive(Deserialize)]
struct UpdatePenaltyStatusRequest {
    status: String,
}

#[derive(Serialize)]
struct UpdatePenaltyStatusResponse {
    penalty_id: i32,
    rosca_id: i32,
    user_id: i32,
    amount: f64,
    status: String,
    updated_at: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
pub async fn update_penalty_status(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path((rosca_id, penalty_id)): Path<(i32, i32)>,
    Json(request): Json<UpdatePenaltyStatusRequest>,
) -> Result<Json<UpdatePenaltyStatusResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Updating penalty status for penalty_id: {} in rosca_id: {} by user_id: {}", penalty_id, rosca_id, auth_user.user_id);
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

    // Validate status
    let valid_statuses = vec!["pending", "applied", "waived"];
    if !valid_statuses.contains(&request.status.as_str()) {
        error!("Invalid penalty status: {}", request.status);
        return Err((StatusCode::BAD_REQUEST, "Invalid penalty status".to_string()));
    }

    // Check if penalty exists and belongs to the ROSCA
    let penalty_exists = sqlx::query!(
        "SELECT 1 FROM contribution_penalties WHERE penalty_id = $1 AND rosca_id = $2",
        penalty_id,
        rosca_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking penalty: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if !penalty_exists {
        error!("Penalty penalty_id: {} not found in rosca_id: {}", penalty_id, rosca_id);
        return Err((StatusCode::NOT_FOUND, "Penalty not found in this ROSCA".to_string()));
    }

    // Update penalty status
    let penalty = sqlx::query_as!(
        UpdatePenaltyStatusResponse,
        r#"
        UPDATE contribution_penalties
        SET 
            status = $1,
            updated_at = NOW()
        WHERE rosca_id = $2 AND penalty_id = $3
        RETURNING penalty_id, rosca_id, user_id, amount, status, updated_at
        "#,
        request.status,
        rosca_id,
        penalty_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error updating penalty status: {}", e); (StatusCode::NOT_FOUND, "Penalty not found".to_string()) })?;

    info!("Penalty status updated: penalty_id={} in rosca_id={} to status={}", penalty_id, rosca_id, penalty.status);
    Ok(Json(penalty))
}
