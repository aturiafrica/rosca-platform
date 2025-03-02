// src/handlers/settings.rs
// Settings endpoint handlers for the ROSCA Platform API
// Manages ROSCA-specific settings

use axum::{http::{StatusCode, HeaderValue}, extract::{State, Path}, Json};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{debug, error, info, instrument};
use chrono::{DateTime, Utc};
use crate::handlers::auth::extract_auth_user;

// Authentication extractor
struct AuthUser { user_id: i32; }

// Endpoint: GET /api/v1/roscas/:rosca_id/settings - Retrieve ROSCA settings
#[derive(Serialize, sqlx::FromRow)]
struct Settings {
    rosca_id: i32,
    cycle_type: String, // e.g., "daily", "monthly", "yearly"
    cycle_length: i32, // length in days
    contribution_amount: Option<f64>,
    payout_rules: serde_json::Value, // JSON blob for payout rules (e.g., {"payout_cycle": 3})
    membership_rules_prefs: serde_json::Value, // JSON blob for membership rules (e.g., {"require_approval": true})
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id))]
pub async fn get_settings(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path(rosca_id): Path<i32>,
) -> Result<Json<Settings>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Fetching settings for rosca_id: {} by user_id: {}", rosca_id, auth_user.user_id);
    tracing::Span::current().record("user_id", &auth_user.user_id);

    // Check if user is an admin member of the ROSCA
    let is_admin = sqlx::query_scalar!(
        "SELECT 1 FROM rosca_members WHERE rosca_id = $1 AND user_id = $2 AND member_type = 'admin'",
        rosca_id,
        auth_user.user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking admin membership: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if !is_admin {
        let rosca_exists = sqlx::query!("SELECT 1 FROM roscas WHERE rosca_id = $1", rosca_id)
            .fetch_optional(&pool)
            .await
            .map_err(|e| { error!("Database error checking ROSCA existence: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
            .is_some();

        if rosca_exists {
            error!("User {} is not an admin member of rosca_id: {}", auth_user.user_id, rosca_id);
            return Err((StatusCode::FORBIDDEN, "User is not an admin member of this ROSCA".to_string()));
        } else {
            error!("ROSCA not found: rosca_id={}", rosca_id);
            return Err((StatusCode::NOT_FOUND, "ROSCA not found".to_string()));
        }
    }

    // Fetch ROSCA settings
    let settings = sqlx::query_as!(
        Settings,
        r#"
        SELECT 
            rosca_id,
            cycle_type,
            cycle_length,
            contribution_amount,
            payout_rules,
            membership_rules_prefs,
            created_at,
            updated_at
        FROM rosca_settings
        WHERE rosca_id = $1
        "#,
        rosca_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { 
        error!("Database error fetching settings: {}", e); 
        if e.as_database_error().map(|de| de.code() == Some("23503")).unwrap_or(false) {
            (StatusCode::NOT_FOUND, "Settings not found for this ROSCA".to_string())
        } else {
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
        }
    })?;

    info!("Retrieved settings for rosca_id: {} by user_id: {}", rosca_id, auth_user.user_id);
    Ok(Json(settings))
}

// Endpoint: PATCH /api/v1/roscas/:rosca_id/settings - Update ROSCA settings
#[derive(Deserialize)]
struct UpdateSettingsRequest {
    cycle_type: Option<String>,
    cycle_length: Option<i32>,
    contribution_amount: Option<f64>,
    payout_rules: Option<serde_json::Value>,
    membership_rules_prefs: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct UpdateSettingsResponse {
    rosca_id: i32,
    cycle_type: String,
    cycle_length: i32,
    contribution_amount: Option<f64>,
    payout_rules: serde_json::Value,
    membership_rules_prefs: serde_json::Value,
    updated_at: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id))]
pub async fn update_settings(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path(rosca_id): Path<i32>,
    Json(request): Json<UpdateSettingsRequest>,
) -> Result<Json<UpdateSettingsResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Updating settings for rosca_id: {} by user_id: {}", rosca_id, auth_user.user_id);
    tracing::Span::current().record("user_id", &auth_user.user_id);

    // Check if user is an admin member of the ROSCA
    let is_admin = sqlx::query_scalar!(
        "SELECT 1 FROM rosca_members WHERE rosca_id = $1 AND user_id = $2 AND member_type = 'admin'",
        rosca_id,
        auth_user.user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking admin membership: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if !is_admin {
        let rosca_exists = sqlx::query!("SELECT 1 FROM roscas WHERE rosca_id = $1", rosca_id)
            .fetch_optional(&pool)
            .await
            .map_err(|e| { error!("Database error checking ROSCA existence: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
            .is_some();

        if rosca_exists {
            error!("User {} is not an admin member of rosca_id: {}", auth_user.user_id, rosca_id);
            return Err((StatusCode::FORBIDDEN, "User is not an admin member of this ROSCA".to_string()));
        } else {
            error!("ROSCA not found: rosca_id={}", rosca_id);
            return Err((StatusCode::NOT_FOUND, "ROSCA not found".to_string()));
        }
    }

    // Validate request data (if provided)
    if let Some(ref cycle_type) = request.cycle_type {
        let valid_cycle_types = vec!["daily", "monthly", "yearly"];
        if !valid_cycle_types.contains(&cycle_type.as_str()) {
            error!("Invalid cycle type: {}", cycle_type);
            return Err((StatusCode::BAD_REQUEST, format!("Invalid cycle type. Supported: {:?}", valid_cycle_types)));
        }
    }
    if let Some(cycle_length) = request.cycle_length {
        if cycle_length < 1 || cycle_length > 365 {
            error!("Invalid cycle length: {}", cycle_length);
            return Err((StatusCode::BAD_REQUEST, "Cycle length must be between 1 and 365 days".to_string()));
        }
    }
    if let Some(contribution_amount) = request.contribution_amount {
        if contribution_amount <= 0.0 {
            error!("Invalid contribution amount: {}", contribution_amount);
            return Err((StatusCode::BAD_REQUEST, "Contribution amount must be positive".to_string()));
        }
    }
    // Basic validation for JSON fields (ensure they’re objects, not exhaustive parsing)
    if let Some(ref payout_rules) = request.payout_rules {
        if !payout_rules.is_object() {
            error!("Invalid payout rules format: must be a JSON object");
            return Err((StatusCode::BAD_REQUEST, "Payout rules must be a JSON object".to_string()));
        }
    }
    if let Some(ref membership_rules_prefs) = request.membership_rules_prefs {
        if !membership_rules_prefs.is_object() {
            error!("Invalid membership rules prefs format: must be a JSON object");
            return Err((StatusCode::BAD_REQUEST, "Membership rules preferences must be a JSON object".to_string()));
        }
    }

    // Check if settings exist for the ROSCA
    let settings_exists = sqlx::query!(
        "SELECT 1 FROM rosca_settings WHERE rosca_id = $1",
        rosca_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking settings: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if !settings_exists {
        error!("Settings not found for rosca_id: {}", rosca_id);
        return Err((StatusCode::NOT_FOUND, "Settings not found for this ROSCA".to_string()));
    }

    // Update ROSCA settings
    let updated_settings = sqlx::query_as!(
        UpdateSettingsResponse,
        r#"
        UPDATE rosca_settings
        SET 
            cycle_type = COALESCE($1, cycle_type),
            cycle_length = COALESCE($2, cycle_length),
            contribution_amount = COALESCE($3, contribution_amount),
            payout_rules = COALESCE($4, payout_rules),
            membership_rules_prefs = COALESCE($5, membership_rules_prefs),
            updated_at = NOW()
        WHERE rosca_id = $6
        RETURNING rosca_id, cycle_type, cycle_length, contribution_amount, payout_rules, membership_rules_prefs, updated_at
        "#,
        request.cycle_type,
        request.cycle_length,
        request.contribution_amount,
        request.payout_rules,
        request.membership_rules_prefs,
        rosca_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error updating settings: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    info!("Settings updated for rosca_id: {} by user_id: {}", rosca_id, auth_user.user_id);
    Ok(Json(updated_settings))
}
