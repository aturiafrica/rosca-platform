// src/handlers/contribution.rs
// Contribution endpoint handlers for the ROSCA Platform API

use axum::{http::{StatusCode, HeaderValue}, extract::{State, Path, Query}, Json};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{debug, error, info, instrument};
use chrono::{DateTime, Utc};
use crate::handlers::auth::extract_auth_user;

// Authentication extractor
struct AuthUser { user_id: i32; }

// Endpoint 7: GET /api/v1/roscas/:rosca_id/contributions - List contributions
#[derive(Deserialize)]
struct ContributionFilter {
    status: Option<String>,
    user_id: Option<i32>,
    cycle_number: Option<i32>,
    limit: Option<i32>,
    offset: Option<i32>,
}

#[derive(Serialize, sqlx::FromRow)]
struct Contribution {
    contribution_id: i32,
    rosca_id: i32,
    user_id: i32,
    username: String,
    amount: f64,
    cycle_number: i32,
    status: String,
    paid_at: Option<DateTime<Utc>,
    created_at: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
pub async fn list_contributions(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path(rosca_id): Path<i32>,
    Query(filter): Query<ContributionFilter>,
) -> Result<Json<Vec<Contribution>>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Listing contributions for rosca_id: {} by user_id: {}", rosca_id, auth_user.user_id);
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

    // Apply filters for contributions
    let limit = filter.limit.unwrap_or(50).max(1).min(100);
    let offset = filter.offset.unwrap_or(0).max(0);
    let mut conditions = vec!["c.rosca_id = $1"];
    let mut params: Vec<&(dyn sqlx::Encode<'_, sqlx::Postgres> + sqlx::Type<sqlx::Postgres> + Sync)> = vec![&rosca_id];
    let mut param_index = 2;

    if let Some(ref status) = filter.status {
        conditions.push(format!("c.status = ${}", param_index));
        params.push(status);
        param_index += 1;
    }
    if let Some(user_id) = filter.user_id {
        conditions.push(format!("c.user_id = ${}", param_index));
        params.push(&user_id);
        param_index += 1;
    }
    if let Some(cycle_number) = filter.cycle_number {
        conditions.push(format!("c.cycle_number = ${}", param_index));
        params.push(&cycle_number);
        param_index += 1;
    }

    // Fetch contributions with pagination
    let query = format!(
        r#"
        SELECT 
            c.contribution_id,
            c.rosca_id,
            c.user_id,
            u.username,
            c.amount,
            c.cycle_number,
            c.status,
            c.paid_at,
            c.created_at
        FROM contributions c
        JOIN users u ON c.user_id = u.user_id
        {}
        ORDER BY c.created_at DESC
        LIMIT ${} OFFSET ${}
        "#,
        if conditions.is_empty() { "WHERE c.rosca_id = $1" } else { format!("WHERE {}", conditions.join(" AND ")) },
        param_index,
        param_index + 1
    );
    params.push(&limit);
    params.push(&offset);

    let contributions = sqlx::query_as_with::<_, Contribution, _>(&query, params)
        .fetch_all(&pool)
        .await
        .map_err(|e| { error!("Database error fetching contributions: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    info!("Retrieved {} contributions for rosca_id: {}", contributions.len(), rosca_id);
    Ok(Json(contributions))
}

// Endpoint 8: POST /api/v1/roscas/:rosca_id/contributions - Create a contribution
#[derive(Deserialize)]
struct CreateContributionRequest {
    user_id: i32,
    amount: f64,
    cycle_number: i32,
}

#[derive(Serialize)]
struct CreateContributionResponse {
    contribution_id: i32,
    rosca_id: i32,
    user_id: i32,
    amount: f64,
    cycle_number: i32,
    status: String,
    created_at: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
pub async fn create_contribution(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path(rosca_id): Path<i32>,
    Json(request): Json<CreateContributionRequest>,
) -> Result<Json<CreateContributionResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Creating contribution for rosca_id: {} by user_id: {}", rosca_id, auth_user.user_id);
    tracing::Span::current()
        .record("user_id", &auth_user.user_id)
        .record("rosca_id", &rosca_id);

    // Check if user is any member of the ROSCA (not just admin)
    let is_member = sqlx::query_scalar!(
        "SELECT 1 FROM rosca_members WHERE rosca_id = $1 AND user_id = $2",
        rosca_id,
        auth_user.user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking membership: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if !is_member {
        let rosca_exists = sqlx::query!("SELECT 1 FROM roscas WHERE rosca_id = $1", rosca_id)
            .fetch_optional(&pool)
            .await
            .map_err(|e| { error!("Database error checking ROSCA existence: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
            .is_some();

        if rosca_exists {
            error!("User {} is not a member of rosca_id: {}", auth_user.user_id, rosca_id);
            return Err((StatusCode::FORBIDDEN, "User is not a member of this ROSCA".to_string()));
        } else {
            error!("ROSCA not found: rosca_id={}", rosca_id);
            return Err((StatusCode::NOT_FOUND, "ROSCA not found".to_string()));
        }
    }

    // Validate request data
    if request.amount <= 0.0 {
        error!("Invalid contribution amount: {}", request.amount);
        return Err((StatusCode::BAD_REQUEST, "Contribution amount must be positive".to_string()));
    }
    if request.cycle_number < 0 {
        error!("Invalid cycle number: {}", request.cycle_number);
        return Err((StatusCode::BAD_REQUEST, "Cycle number must be non-negative".to_string()));
    }

    // Check if the target user is a member of the ROSCA and their status
    let member_status = sqlx::query_scalar!(
        "SELECT status FROM rosca_members WHERE rosca_id = $1 AND user_id = $2",
        rosca_id,
        request.user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking member status: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    let status = match member_status {
        Some(s) => s,
        None => {
            error!("User {} is not a member of rosca_id: {}", request.user_id, rosca_id);
            return Err((StatusCode::BAD_REQUEST, "Target user is not a member of this ROSCA".to_string()));
        }
    };

    // Check membership rules for verification requirement
    let require_approval = sqlx::query_scalar!(
        "SELECT membership_rules_prefs->>'require_approval' FROM rosca_settings WHERE rosca_id = $1",
        rosca_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error fetching membership rules: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .unwrap_or("true") == "true"; // Default to requiring approval if not set

    if require_approval && status == "pending" {
        error!("User {} is pending verification and cannot contribute to rosca_id: {}", request.user_id, rosca_id);
        return Err((StatusCode::FORBIDDEN, "User is pending verification and cannot contribute".to_string()));
    }

    // Fetch ROSCA contribution amount for validation
    let rosca_amount = sqlx::query_scalar!(
        "SELECT contribution_amount FROM roscas WHERE rosca_id = $1",
        rosca_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error fetching ROSCA details: {}", e); (StatusCode::NOT_FOUND, "ROSCA not found".to_string()) })?;

    if request.amount != rosca_amount {
        error!("Contribution amount {} does not match ROSCA required amount: {}", request.amount, rosca_amount);
        return Err((StatusCode::BAD_REQUEST, format!("Contribution amount must be {}", rosca_amount)));
    }

    // Create the contribution
    let contribution = sqlx::query_as!(
        CreateContributionResponse,
        r#"
        INSERT INTO contributions (rosca_id, user_id, amount, cycle_number, status)
        VALUES ($1, $2, $3, $4, 'pending')
        RETURNING contribution_id, rosca_id, user_id, amount, cycle_number, status, created_at
        "#,
        rosca_id,
        request.user_id,
        request.amount,
        request.cycle_number
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error creating contribution: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    // Update member status to "active" if this is their first contribution and not already active
    if status != "active" {
        let has_prior_contribution = sqlx::query_scalar!(
            "SELECT 1 FROM contributions WHERE rosca_id = $1 AND user_id = $2 AND contribution_id != $3",
            rosca_id,
            request.user_id,
            contribution.contribution_id
        )
        .fetch_optional(&pool)
        .await
        .map_err(|e| { error!("Database error checking prior contributions: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
        .is_some();

        if !has_prior_contribution {
            sqlx::query!(
                "UPDATE rosca_members SET status = 'active' WHERE rosca_id = $1 AND user_id = $2",
                rosca_id,
                request.user_id
            )
            .execute(&pool)
            .await
            .map_err(|e| { error!("Database error updating member status: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;
            info!("Member user_id: {} status updated to 'active' for rosca_id: {}", request.user_id, rosca_id);
        }
    }

    info!("Contribution created: contribution_id={} for rosca_id={} with status={}", contribution.contribution_id, rosca_id, contribution.status);
    Ok(Json(contribution))
}

// Endpoint 9: PATCH /api/v1/roscas/:rosca_id/contributions/:contribution_id/status - Update contribution status
#[derive(Deserialize)]
struct UpdateContributionStatusRequest {
    status: String,
}

#[derive(Serialize)]
struct UpdateContributionStatusResponse {
    contribution_id: i32,
    rosca_id: i32,
    user_id: i32,
    amount: f64,
    cycle_number: i32,
    status: String,
    paid_at: Option<DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
pub async fn update_contribution_status(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path((rosca_id, contribution_id)): Path<(i32, i32)>,
    Json(request): Json<UpdateContributionStatusRequest>,
) -> Result<Json<UpdateContributionStatusResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Updating contribution status for contribution_id: {} in rosca_id: {} by user_id: {}", contribution_id, rosca_id, auth_user.user_id);
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
    let valid_statuses = vec!["pending", "completed", "rejected"];
    if !valid_statuses.contains(&request.status.as_str()) {
        error!("Invalid contribution status: {}", request.status);
        return Err((StatusCode::BAD_REQUEST, "Invalid contribution status".to_string()));
    }

    // Check if contribution exists and belongs to the ROSCA
    let contribution_exists = sqlx::query!(
        "SELECT 1 FROM contributions WHERE contribution_id = $1 AND rosca_id = $2",
        contribution_id,
        rosca_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking contribution: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if !contribution_exists {
        error!("Contribution contribution_id: {} not found in rosca_id: {}", contribution_id, rosca_id);
        return Err((StatusCode::NOT_FOUND, "Contribution not found in this ROSCA".to_string()));
    }

    // Update contribution status
    let contribution = sqlx::query_as!(
        UpdateContributionStatusResponse,
        r#"
        UPDATE contributions
        SET 
            status = $1,
            paid_at = CASE 
                WHEN $1 = 'completed' AND paid_at IS NULL THEN NOW() 
                WHEN $1 IN ('pending', 'rejected') THEN NULL 
                ELSE paid_at 
            END,
            updated_at = NOW()
        WHERE rosca_id = $2 AND contribution_id = $3
        RETURNING contribution_id, rosca_id, user_id, amount, cycle_number, status, paid_at, updated_at
        "#,
        request.status,
        rosca_id,
        contribution_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error updating contribution status: {}", e); (StatusCode::NOT_FOUND, "Contribution not found".to_string()) })?;

    info!("Contribution status updated: contribution_id={} in rosca_id={} to status={}", contribution_id, rosca_id, contribution.status);
    Ok(Json(contribution))
}
