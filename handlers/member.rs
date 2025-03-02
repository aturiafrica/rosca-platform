// src/handlers/member.rs
// Member endpoint handlers for the ROSCA Platform API

use axum::{http::{StatusCode, HeaderValue}, extract::{State, Path}, Json};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{debug, error, info, instrument};
use chrono::{DateTime, Utc};
use crate::handlers::auth::extract_auth_user;

// Authentication extractor
struct AuthUser { user_id: i32; }

// Endpoint 11: GET /api/v1/roscas/:rosca_id/members - List members
#[derive(Serialize, sqlx::FromRow)]
struct Member {
    user_id: i32,
    username: String,
    status: String,
    member_type: String,
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
pub async fn list_members(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path(rosca_id): Path<i32>,
) -> Result<Json<Vec<Member>>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Listing members for rosca_id: {} by user_id: {}", rosca_id, auth_user.user_id);
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

    // Fetch member list
    let members = sqlx::query_as!(
        Member,
        r#"
        SELECT rm.user_id, u.username, rm.status, rm.member_type
        FROM rosca_members rm
        JOIN users u ON rm.user_id = u.user_id
        WHERE rm.rosca_id = $1
        ORDER BY rm.joined_at
        "#,
        rosca_id
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| { error!("Database error fetching members: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    info!("Retrieved {} members for rosca_id: {}", members.len(), rosca_id);
    Ok(Json(members))
}

// Endpoint 12: POST /api/v1/roscas/:rosca_id/members - Propose a member
#[derive(Deserialize)]
struct ProposeMemberRequest {
    username: String,
}

#[derive(Serialize)]
struct ProposeMemberResponse {
    rosca_id: i32,
    user_id: i32,
    status: String,
    member_type: String,
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
pub async fn propose_member(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path(rosca_id): Path<i32>,
    Json(request): Json<ProposeMemberRequest>,
) -> Result<Json<ProposeMemberResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Proposing member for rosca_id: {} by user_id: {}", rosca_id, auth_user.user_id);
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

    // Fetch the user_id from the provided username
    let user_id = sqlx::query_scalar!(
        "SELECT user_id FROM users WHERE username = $1",
        request.username
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("User not found: {}", e); (StatusCode::NOT_FOUND, "User not found".to_string()) })?;

    // Check if the user is already a member
    let existing_member = sqlx::query_scalar!(
        "SELECT 1 FROM rosca_members WHERE rosca_id = $1 AND user_id = $2",
        rosca_id,
        user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking existing member: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if existing_member {
        error!("User {} is already a member of rosca_id: {}", user_id, rosca_id);
        return Err((StatusCode::CONFLICT, "User is already a member of this ROSCA".to_string()));
    }

    // Propose the member with "pending" status (active status requires first contribution)
    let member = sqlx::query_as!(
        ProposeMemberResponse,
        r#"
        INSERT INTO rosca_members (rosca_id, user_id, status, member_type)
        VALUES ($1, $2, 'pending', 'member')
        RETURNING rosca_id, user_id, status, member_type
        "#,
        rosca_id,
        user_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error proposing member: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    info!("Member proposed: user_id={} for rosca_id={} with status={}", user_id, rosca_id, member.status);
    Ok(Json(member))
}

// Endpoint 13: PATCH /api/v1/roscas/:rosca_id/members/:username/status - Update member status
#[derive(Deserialize)]
struct UpdateMemberStatusRequest {
    status: String,
}

#[derive(Serialize)]
struct UpdateMemberStatusResponse {
    rosca_id: i32,
    user_id: i32,
    status: String,
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
pub async fn update_member_status(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path((rosca_id, username)): Path<(i32, String)>,
    Json(request): Json<UpdateMemberStatusRequest>,
) -> Result<Json<UpdateMemberStatusResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Updating member status for rosca_id: {} username: {} by user_id: {}", rosca_id, username, auth_user.user_id);
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

    // Fetch the user_id from the provided username
    let user_id = sqlx::query_scalar!(
        "SELECT user_id FROM users WHERE username = $1",
        username
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("User not found: {}", e); (StatusCode::NOT_FOUND, "User not found".to_string()) })?;

    // Check if the member exists in the ROSCA
    let current_member = sqlx::query!(
        "SELECT status FROM rosca_members WHERE rosca_id = $1 AND user_id = $2",
        rosca_id,
        user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking member: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    let current_status = match current_member {
        Some(m) => m.status,
        None => {
            error!("Member {} not found in rosca_id: {}", username, rosca_id);
            return Err((StatusCode::NOT_FOUND, "Member not found in this ROSCA".to_string()));
        }
    };

    // Validate status transition
    let valid_statuses = vec!["pending", "active", "inactive", "rejected"];
    if !valid_statuses.contains(&request.status.as_str()) {
        error!("Invalid status: {}", request.status);
        return Err((StatusCode::BAD_REQUEST, "Invalid status value".to_string()));
    }

    // Check membership rules for verification requirement
    let require_approval = sqlx::query_scalar!(
        "SELECT membership_rules_prefs->>'require_approval' FROM rosca_settings WHERE rosca_id = $1",
        rosca_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error fetching membership rules: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .unwrap_or("true") == "true"; // Default to requiring approval if not set

    // Prevent "active" status unless first contribution is paid (except for "inactive" or "rejected")
    if request.status == "active" && current_status != "active" {
        let has_contribution = sqlx::query_scalar!(
            "SELECT 1 FROM contributions WHERE rosca_id = $1 AND user_id = $2 AND status = 'completed'",
            rosca_id,
            user_id
        )
        .fetch_optional(&pool)
        .await
        .map_err(|e| { error!("Database error checking contributions: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
        .is_some();

        if !has_contribution {
            error!("Cannot set status to 'active' for user_id: {} in rosca_id: {} without a completed contribution", user_id, rosca_id);
            return Err((StatusCode::BAD_REQUEST, "Member must pay first contribution to become active".to_string()));
        }
    }

    // Update member status
    let member = sqlx::query_as!(
        UpdateMemberStatusResponse,
        r#"
        UPDATE rosca_members
        SET status = $1
        WHERE rosca_id = $2 AND user_id = $3
        RETURNING rosca_id, user_id, status
        "#,
        request.status,
        rosca_id,
        user_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error updating member status: {}", e); (StatusCode::NOT_FOUND, "Member not found".to_string()) })?;

    info!("Member status updated: user_id={} in rosca_id={} to status={}", user_id, rosca_id, member.status);
    Ok(Json(member))
}

// Endpoint 79: DELETE /api/v1/roscas/:rosca_id/members/:user_id - Remove a member
#[derive(Serialize)]
struct DeleteMemberResponse {
    rosca_id: i32,
    user_id: i32,
    message: String,
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
pub async fn delete_member(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path((rosca_id, user_id)): Path<(i32, i32)>,
) -> Result<Json<DeleteMemberResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Deleting member user_id: {} from rosca_id: {} by user_id: {}", user_id, rosca_id, auth_user.user_id);
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

    // Check if the member exists in the ROSCA
    let member_exists = sqlx::query!(
        "SELECT 1 FROM rosca_members WHERE rosca_id = $1 AND user_id = $2",
        rosca_id,
        user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking member: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if !member_exists {
        error!("Member user_id: {} not found in rosca_id: {}", user_id, rosca_id);
        return Err((StatusCode::NOT_FOUND, "Member not found in this ROSCA".to_string()));
    }

    // Check for active financial obligations
    let has_contributions = sqlx::query_scalar!(
        "SELECT 1 FROM contributions WHERE rosca_id = $1 AND user_id = $2 AND status = 'completed'",
        rosca_id,
        user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking contributions: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    let has_loans = sqlx::query_scalar!(
        "SELECT 1 FROM loans WHERE rosca_id = $1 AND user_id = $2 AND status = 'active'",
        rosca_id,
        user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking loans: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    let has_payouts = sqlx::query_scalar!(
        "SELECT 1 FROM payouts WHERE rosca_id = $1 AND user_id = $2 AND payout_status = 'completed'",
        rosca_id,
        user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking payouts: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if has_contributions || has_loans || has_payouts {
        error!("Cannot delete member user_id: {} from rosca_id: {} due to active financial obligations", user_id, rosca_id);
        return Err((StatusCode::BAD_REQUEST, "Member has active financial obligations".to_string()));
    }

    // Delete the member
    let result = sqlx::query!(
        "DELETE FROM rosca_members WHERE rosca_id = $1 AND user_id = $2 RETURNING user_id",
        rosca_id,
        user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error deleting member: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    if result.is_none() {
        error!("Member user_id: {} not found in rosca_id: {}", user_id, rosca_id);
        return Err((StatusCode::NOT_FOUND, "Member not found".to_string()));
    }

    info!("Member user_id: {} deleted from rosca_id: {}", user_id, rosca_id);
    Ok(Json(DeleteMemberResponse {
        rosca_id,
        user_id,
        message: "Member removed successfully".to_string(),
    }))
}

// Endpoint 80: GET /api/v1/roscas/:rosca_id/members/:user_id - Get member details
#[derive(Serialize, sqlx::FromRow)]
struct MemberDetail {
    rosca_name: String,        
    user_id: i32,
    username: String,
    status: String,
    member_type: String,
    interest_rate: Option<f64>,
    qualifies_for_loan: bool,
    can_receive_payout: bool,
    joined_at: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
pub async fn get_member(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path((rosca_id, user_id)): Path<(i32, i32)>,
) -> Result<Json<MemberDetail>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Retrieving member details for user_id: {} in rosca_id: {} by user_id: {}", user_id, rosca_id, auth_user.user_id);
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

    // Fetch member details with rosca_name
    let member = sqlx::query_as!(
        MemberDetail,
        r#"
        SELECT 
            r.name AS rosca_name,
            rm.user_id,
            u.username,
            rm.status,
            rm.member_type,
            rm.interest_rate,
            rm.qualifies_for_loan,
            rm.can_receive_payout,
            rm.joined_at
        FROM rosca_members rm
        JOIN users u ON rm.user_id = u.user_id
        JOIN roscas r ON rm.rosca_id = r.rosca_id
        WHERE rm.rosca_id = $1 AND rm.user_id = $2
        "#,
        rosca_id,
        user_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error fetching member details: {}", e); (StatusCode::NOT_FOUND, "Member not found in this ROSCA".to_string()) })?;

    info!("Member details retrieved: user_id={} in rosca_name: {}", user_id, member.rosca_name);
    Ok(Json(member))
}
