// src/handlers/rosca.rs
// ROSCA endpoint handlers for the ROSCA Platform API

use axum::{http::{StatusCode, HeaderValue, HeaderMap}, extract::{State, Path, Query}, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::PgPool;
use tracing::{debug, error, info, instrument};
use chrono::{DateTime, Utc, Duration};
use printpdf::*;
use rust_xlsxwriter::Workbook;
use std::io::Cursor;
use crate::handlers::auth::extract_auth_user;

// Authentication extractor
struct AuthUser { user_id: i32; }

// Endpoint 24: POST /api/v1/roscas - Create a ROSCA
#[derive(Deserialize)]
struct CreateRoscaRequest {
    name: String,
    contribution_amount: f64,
    #[serde(default)]
    description: Option<String>,
    #[serde(default = "default_rosca_type")]
    rosca_type: String,
    #[serde(default = "default_member_entry_requirement")]
    member_entry_requirement: String,
    #[serde(default = "default_cycle_type")]
    cycle_type: String,
    #[serde(default)]
    payout_cycle: Option<i32>,
    #[serde(default)]
    payout_cycle_type: Option<String>,
    #[serde(default)]
    interest_rate: Option<f64>,
}

fn default_rosca_type() -> String { "ordinary".to_string() }
fn default_member_entry_requirement() -> String { "none".to_string() }
fn default_cycle_type() -> String { "monthly".to_string() }

#[derive(Serialize)]
struct RoscaResponse {
    rosca_id: i32,
    name: String,
    contribution_amount: f64,
    cycle_length: i32,
    cycle_type: String,
    payout_cycle: Option<i32>,
    payout_cycle_type: Option<String>,
    rosca_type: String,
    description: Option<String>,
    member_entry_requirement: String,
    status: String,
    creator_id: i32,
    member_type: String,
    total_members: i64,
    active_members: i64,
    interest_rate: Option<f64>,
    created_at: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id))]
async fn create_rosca(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Json(payload): Json<CreateRoscaRequest>,
) -> Result<(StatusCode, JsonResponse<RoscaResponse>), (StatusCode, String)> {
    debug!("Validating JWT from Authorization header");
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Received request to create ROSCA by user_id: {}", auth_user.user_id);
    tracing::Span::current().record("user_id", &auth_user.user_id);

    // Validate input
    debug!("Validating ROSCA parameters");
    if payload.name.trim().is_empty() || payload.contribution_amount <= 0.0 {
        error!("Invalid basic parameters: name={}, contribution_amount={}", payload.name, payload.contribution_amount);
        return Err((StatusCode::BAD_REQUEST, "Invalid ROSCA parameters".to_string()));
    }

    let valid_rosca_types = vec!["ordinary", "investment", "holiday", "health", "emergency", "school fees", "burial", "hire purchase", "loans"];
    let valid_entry_requirements = vec!["none", "proposed", "verified", "both"];
    let valid_cycle_types = vec!["daily", "weekly", "monthly", "yearly", "member_size"];
    if !valid_rosca_types.contains(&payload.rosca_type.as_str()) ||
       !valid_entry_requirements.contains(&payload.member_entry_requirement.as_str()) ||
       !valid_cycle_types.contains(&payload.cycle_type.as_str()) ||
       payload.payout_cycle.map_or(false, |pc| pc <= 0) ||
       (payload.payout_cycle_type.is_some() && !valid_cycle_types.contains(&payload.payout_cycle_type.as_ref().unwrap().as_str())) ||
       payload.interest_rate.map_or(false, |ir| ir < 0.0) {
        error!("Invalid enum or numeric parameters: rosca_type={}, member_entry_requirement={}, cycle_type={}, payout_cycle={:?}, payout_cycle_type={:?}, interest_rate={:?}", 
            payload.rosca_type, payload.member_entry_requirement, payload.cycle_type, payload.payout_cycle, payload.payout_cycle_type, payload.interest_rate);
        return Err((StatusCode::BAD_REQUEST, "Invalid ROSCA parameters".to_string()));
    }

    // Begin transaction
    let mut tx = pool.begin().await
        .map_err(|e| { error!("Failed to start transaction: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    // Insert into roscas
    debug!("Inserting new ROSCA into database");
    let rosca = sqlx::query!(
        r#"
        INSERT INTO roscas (name, creator_id, contribution_amount, description, rosca_type, member_entry_requirement, cycle_type, payout_cycle, payout_cycle_type, interest_rate)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING rosca_id, cycle_length, status, created_at
        "#,
        payload.name,
        auth_user.user_id,
        payload.contribution_amount,
        payload.description,
        payload.rosca_type,
        payload.member_entry_requirement,
        payload.cycle_type,
        payload.payout_cycle,
        payload.payout_cycle_type,
        payload.interest_rate
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        if e.to_string().contains("duplicate key value") {
            error!("ROSCA name {} already exists", payload.name);
            (StatusCode::CONFLICT, "ROSCA name already exists".to_string())
        } else {
            error!("Database error inserting ROSCA: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
        }
    })?;

    // Insert creator as admin member
    debug!("Adding user_id: {} as admin member to rosca_id: {}", auth_user.user_id, rosca.rosca_id);
    sqlx::query!(
        r#"
        INSERT INTO rosca_members (rosca_id, user_id, proposed_by, status, member_type)
        VALUES ($1, $2, $2, 'active', 'admin')
        "#,
        rosca.rosca_id,
        auth_user.user_id
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| { error!("Database error inserting admin member: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    // Commit transaction
    tx.commit().await
        .map_err(|e| { error!("Failed to commit transaction: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    // Fetch full response after triggers (e.g., cycle_length adjustment)
    debug!("Fetching full ROSCA details after creation");
    let response = sqlx::query_as!(
        RoscaResponse,
        r#"
        SELECT 
            r.rosca_id,
            r.name,
            r.contribution_amount,
            r.cycle_length,
            r.cycle_type,
            r.payout_cycle,
            r.payout_cycle_type,
            r.rosca_type,
            r.description,
            r.member_entry_requirement,
            r.status,
            r.creator_id,
            rm.member_type,
            (SELECT COUNT(*) FROM rosca_members rm2 WHERE rm2.rosca_id = r.rosca_id) AS "total_members!",
            (SELECT COUNT(*) FROM rosca_members rm3 WHERE rm3.rosca_id = r.rosca_id AND rm3.status = 'active') AS "active_members!",
            r.interest_rate,
            r.created_at
        FROM roscas r
        JOIN rosca_members rm ON r.rosca_id = rm.rosca_id
        WHERE r.rosca_id = $1 AND rm.user_id = $2
        "#,
        rosca.rosca_id,
        auth_user.user_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error fetching ROSCA details: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    info!("ROSCA created successfully: rosca_id={}", response.rosca_id);
    Ok((StatusCode::CREATED, JsonResponse(response)))
}

// Endpoint 25: PATCH /api/v1/roscas/:rosca_id - Update ROSCA details
#[derive(Deserialize)]
struct UpdateRoscaRequest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    contribution_amount: Option<f64>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    rosca_type: Option<String>,
    #[serde(default)]
    member_entry_requirement: Option<String>,
    #[serde(default)]
    cycle_type: Option<String>,
    #[serde(default)]
    payout_cycle: Option<i32>,
    #[serde(default)]
    payout_cycle_type: Option<String>,
    #[serde(default)]
    interest_rate: Option<f64>,
}

#[derive(Serialize)]
struct RoscaResponse {
    rosca_id: i32,
    name: String,
    contribution_amount: f64,
    cycle_length: i32,
    cycle_type: String,
    payout_cycle: Option<i32>,
    payout_cycle_type: Option<String>,
    rosca_type: String,
    description: Option<String>,
    member_entry_requirement: String,
    status: String,
    creator_id: i32,
    member_type: String,
    total_members: i64,
    active_members: i64,
    interest_rate: Option<f64>,
    created_at: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
async fn update_rosca(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path(rosca_id): Path<i32>,
    Json(payload): Json<UpdateRoscaRequest>,
) -> Result<(StatusCode, JsonResponse<RoscaResponse>), (StatusCode, String)> {
    debug!("Validating JWT from Authorization header");
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Received request to update ROSCA for rosca_id: {} by user_id: {}", rosca_id, auth_user.user_id);
    tracing::Span::current()
        .record("user_id", &auth_user.user_id)
        .record("rosca_id", &rosca_id);

    // Validate user is an admin member or platform admin
    debug!("Checking if user_id: {} has admin rights for rosca_id: {}", auth_user.user_id, rosca_id);
    let user_role_info = sqlx::query!(
        r#"
        SELECT rm.member_type, r.role_name
        FROM rosca_members rm
        JOIN users u ON rm.user_id = u.user_id
        JOIN roles r ON u.role_id = r.role_id
        WHERE rm.rosca_id = $1 AND rm.user_id = $2
        "#,
        rosca_id, auth_user.user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking admin rights: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    let (is_admin_member, is_platform_admin) = match user_role_info {
        Some(info) => (info.member_type == "admin", info.role_name == "admin"),
        None => {
            error!("User {} is not a member of rosca_id: {}", auth_user.user_id, rosca_id);
            return Err((StatusCode::FORBIDDEN, "User is not a member of this ROSCA".to_string()));
        }
    };

    if !is_admin_member && !is_platform_admin {
        error!("User {} lacks admin rights for rosca_id: {}", auth_user.user_id, rosca_id);
        return Err((StatusCode::FORBIDDEN, "User is not an admin member or platform admin".to_string()));
    }

    // Validate input
    debug!("Validating ROSCA update parameters");
    if let Some(ref name) = payload.name {
        if name.trim().is_empty() {
            error!("Invalid name: {}", name);
            return Err((StatusCode::BAD_REQUEST, "Invalid ROSCA parameters".to_string()));
        }
    }
    if let Some(amount) = payload.contribution_amount {
        if amount <= 0.0 {
            error!("Invalid contribution_amount: {}", amount);
            return Err((StatusCode::BAD_REQUEST, "Invalid ROSCA parameters".to_string()));
        }
    }
    let valid_rosca_types = vec!["ordinary", "investment", "holiday", "health", "emergency", "school fees", "burial", "hire purchase", "loans"];
    let valid_entry_requirements = vec!["none", "proposed", "verified", "both"];
    let valid_cycle_types = vec!["daily", "weekly", "monthly", "yearly", "member_size"];
    if payload.rosca_type.as_ref().map_or(false, |rt| !valid_rosca_types.contains(&rt.as_str())) ||
       payload.member_entry_requirement.as_ref().map_or(false, |mer| !valid_entry_requirements.contains(&mer.as_str())) ||
       payload.cycle_type.as_ref().map_or(false, |ct| !valid_cycle_types.contains(&ct.as_str())) ||
       payload.payout_cycle.map_or(false, |pc| pc <= 0) ||
       payload.payout_cycle_type.as_ref().map_or(false, |pct| !valid_cycle_types.contains(&pct.as_str())) ||
       payload.interest_rate.map_or(false, |ir| ir < 0.0) {
        error!("Invalid enum or numeric parameters: {:?}", payload);
        return Err((StatusCode::BAD_REQUEST, "Invalid ROSCA parameters".to_string()));
    }

    // Build dynamic update query
    let mut set_clauses: Vec<String> = Vec::new();
    let mut params: Vec<&(dyn sqlx::Encode<'_, sqlx::Postgres> + sqlx::Type<sqlx::Postgres> + Sync)> = vec![];
    let mut param_index = 1;

    if let Some(name) = &payload.name { set_clauses.push(format!("name = ${}", param_index)); params.push(name); param_index += 1; }
    if let Some(amount) = payload.contribution_amount { set_clauses.push(format!("contribution_amount = ${}", param_index)); params.push(&amount); param_index += 1; }
    if payload.description.is_some() { set_clauses.push(format!("description = ${}", param_index)); params.push(&payload.description); param_index += 1; }
    if let Some(rosca_type) = &payload.rosca_type { set_clauses.push(format!("rosca_type = ${}", param_index)); params.push(rosca_type); param_index += 1; }
    if let Some(mer) = &payload.member_entry_requirement { set_clauses.push(format!("member_entry_requirement = ${}", param_index)); params.push(mer); param_index += 1; }
    if let Some(cycle_type) = &payload.cycle_type { set_clauses.push(format!("cycle_type = ${}", param_index)); params.push(cycle_type); param_index += 1; }
    if payload.payout_cycle.is_some() { set_clauses.push(format!("payout_cycle = ${}", param_index)); params.push(&payload.payout_cycle); param_index += 1; }
    if payload.payout_cycle_type.is_some() { set_clauses.push(format!("payout_cycle_type = ${}", param_index)); params.push(&payload.payout_cycle_type); param_index += 1; }
    if payload.interest_rate.is_some() { set_clauses.push(format!("interest_rate = ${}", param_index)); params.push(&payload.interest_rate); param_index += 1; }

    if set_clauses.is_empty() {
        error!("No fields provided to update for rosca_id: {}", rosca_id);
        return Err((StatusCode::BAD_REQUEST, "Invalid ROSCA parameters".to_string()));
    }

    let query = format!(
        r#"
        UPDATE roscas r
        SET {}
        WHERE r.rosca_id = ${}
        RETURNING 
            r.rosca_id,
            r.name,
            r.contribution_amount,
            r.cycle_length,
            r.cycle_type,
            r.payout_cycle,
            r.payout_cycle_type,
            r.rosca_type,
            r.description,
            r.member_entry_requirement,
            r.status,
            r.creator_id,
            (SELECT COUNT(*) FROM rosca_members rm2 WHERE rm2.rosca_id = r.rosca_id) AS "total_members!",
            (SELECT COUNT(*) FROM rosca_members rm3 WHERE rm3.rosca_id = r.rosca_id AND rm3.status = 'active') AS "active_members!",
            r.interest_rate,
            r.created_at
        "#,
        set_clauses.join(", "),
        param_index
    );
    params.push(&rosca_id);

    // Execute update
    debug!("Executing update query: {}", query);
    let rosca = sqlx::query_as_with::<_, RoscaResponse, _>(&query, params)
        .fetch_optional(&pool)
        .await
        .map_err(|e| {
            if e.to_string().contains("duplicate key value") {
                error!("ROSCA name already exists: {:?}", payload.name);
                (StatusCode::CONFLICT, "ROSCA name already exists".to_string())
            } else {
                error!("Database error updating ROSCA: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            }
        })?;

    let rosca = match rosca {
        Some(r) => r,
        None => {
            error!("ROSCA not found: rosca_id={}", rosca_id);
            return Err((StatusCode::NOT_FOUND, "ROSCA not found".to_string()));
        }
    };

    // Fetch member_type separately since it's user-specific
    let member_type = sqlx::query_scalar!(
        "SELECT member_type FROM rosca_members WHERE rosca_id = $1 AND user_id = $2",
        rosca_id, auth_user.user_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error fetching member_type: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    let response = RoscaResponse {
        member_type,
        ..rosca
    };

    info!("ROSCA updated successfully: rosca_id={}", response.rosca_id);
    Ok((StatusCode::OK, JsonResponse(response)))
}


// Endpoint 26: PATCH /api/v1/roscas/:rosca_id/status - Update ROSCA status
#[derive(Deserialize)]
struct UpdateRoscaStatusRequest {
    status: String,
}

#[derive(Serialize)]
struct RoscaResponse {
    rosca_id: i32,
    name: String,
    contribution_amount: f64,
    cycle_length: i32,
    cycle_type: String,
    payout_cycle: Option<i32>,
    payout_cycle_type: Option<String>,
    rosca_type: String,
    description: Option<String>,
    member_entry_requirement: String,
    status: String,
    creator_id: i32,
    member_type: String,
    total_members: i64,
    active_members: i64,
    interest_rate: Option<f64>,
    created_at: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
async fn update_rosca_status(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path(rosca_id): Path<i32>,
    Json(payload): Json<UpdateRoscaStatusRequest>,
) -> Result<(StatusCode, JsonResponse<RoscaResponse>), (StatusCode, String)> {
    debug!("Validating JWT from Authorization header");
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Received request to update ROSCA status for rosca_id: {} by user_id: {}", rosca_id, auth_user.user_id);
    tracing::Span::current()
        .record("user_id", &auth_user.user_id)
        .record("rosca_id", &rosca_id);

    // Validate user is an admin member or platform admin
    debug!("Checking if user_id: {} has admin rights for rosca_id: {}", auth_user.user_id, rosca_id);
    let user_role_info = sqlx::query!(
        r#"
        SELECT rm.member_type, r.role_name
        FROM rosca_members rm
        JOIN users u ON rm.user_id = u.user_id
        JOIN roles r ON u.role_id = r.role_id
        WHERE rm.rosca_id = $1 AND rm.user_id = $2
        "#,
        rosca_id, auth_user.user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking admin rights: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    let (is_admin_member, is_platform_admin) = match user_role_info {
        Some(info) => (info.member_type == "admin", info.role_name == "admin"),
        None => {
            error!("User {} is not a member of rosca_id: {}", auth_user.user_id, rosca_id);
            return Err((StatusCode::FORBIDDEN, "User is not a member of this ROSCA".to_string()));
        }
    };

    if !is_admin_member && !is_platform_admin {
        error!("User {} lacks admin rights for rosca_id: {}", auth_user.user_id, rosca_id);
        return Err((StatusCode::FORBIDDEN, "User is not an admin member or platform admin".to_string()));
    }

    // Validate status
    let valid_statuses = vec!["active", "suspended", "deactivated", "completed"];
    if !valid_statuses.contains(&payload.status.as_str()) {
        error!("Invalid status value: {}", payload.status);
        return Err((StatusCode::BAD_REQUEST, "Invalid status value".to_string()));
    }

    // Update ROSCA status
    debug!("Updating status for rosca_id: {}", rosca_id);
    let rosca = sqlx::query_as!(
        RoscaResponse,
        r#"
        UPDATE roscas r
        SET status = $1
        WHERE r.rosca_id = $2
        RETURNING 
            r.rosca_id,
            r.name,
            r.contribution_amount,
            r.cycle_length,
            r.cycle_type,
            r.payout_cycle,
            r.payout_cycle_type,
            r.rosca_type,
            r.description,
            r.member_entry_requirement,
            r.status,
            r.creator_id,
            (SELECT COUNT(*) FROM rosca_members rm2 WHERE rm2.rosca_id = r.rosca_id) AS "total_members!",
            (SELECT COUNT(*) FROM rosca_members rm3 WHERE rm3.rosca_id = r.rosca_id AND rm3.status = 'active') AS "active_members!",
            r.interest_rate,
            r.created_at,
            (SELECT member_type FROM rosca_members rm WHERE rm.rosca_id = r.rosca_id AND rm.user_id = $3) AS "member_type!"
        "#,
        payload.status,
        rosca_id,
        auth_user.user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error updating ROSCA status: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    let rosca = match rosca {
        Some(r) => r,
        None => {
            error!("ROSCA not found: rosca_id={}", rosca_id);
            return Err((StatusCode::NOT_FOUND, "ROSCA not found".to_string()));
        }
    };

    info!("ROSCA status updated successfully: rosca_id={} to status={}", rosca.rosca_id, rosca.status);
    Ok((StatusCode::OK, JsonResponse(rosca)))
}


// Assumed PATCH: PATCH /api/v1/roscas/:rosca_id/settings - Update ROSCA settings
#[derive(Deserialize)]
struct UpdateRoscaSettingsRequest {
    notification_prefs: Option<JsonValue>,
    payout_rules: Option<JsonValue>,
    membership_rules_prefs: Option<JsonValue>,
    loan_prefs: Option<JsonValue>,
    logo_location: Option<String>,
    contacts: Option<String>,
    rosca_motto: Option<String>,
}

#[derive(Serialize)]
struct UpdateRoscaSettingsResponse {
    rosca_id: i32,
    notification_prefs: JsonValue,
    payout_rules: JsonValue,
    membership_rules_prefs: JsonValue,
    loan_prefs: JsonValue,
    logo_location: Option<String>,
    contacts: Option<String>,
    rosca_motto: Option<String>,
    updated_at: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
pub async fn update_rosca_settings(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path(rosca_id): Path<i32>,
    Json(request): Json<UpdateRoscaSettingsRequest>,
) -> Result<Json<UpdateRoscaSettingsResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Updating settings for rosca_id: {} by user_id: {}", rosca_id, auth_user.user_id);
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

    // Validate JSONB fields if provided (basic structure check)
    if let Some(ref prefs) = request.notification_prefs {
        if !prefs.is_object() {
            error!("Invalid notification_prefs format: must be a JSON object");
            return Err((StatusCode::BAD_REQUEST, "Notification preferences must be a JSON object".to_string()));
        }
    }
    if let Some(ref rules) = request.payout_rules {
        if !rules.is_object() {
            error!("Invalid payout_rules format: must be a JSON object");
            return Err((StatusCode::BAD_REQUEST, "Payout rules must be a JSON object".to_string()));
        }
    }
    if let Some(ref prefs) = request.membership_rules_prefs {
        if !prefs.is_object() {
            error!("Invalid membership_rules_prefs format: must be a JSON object");
            return Err((StatusCode::BAD_REQUEST, "Membership rules preferences must be a JSON object".to_string()));
        }
    }
    if let Some(ref prefs) = request.loan_prefs {
        if !prefs.is_object() {
            error!("Invalid loan_prefs format: must be a JSON object");
            return Err((StatusCode::BAD_REQUEST, "Loan preferences must be a JSON object".to_string()));
        }
    }

    // Update or insert the ROSCA settings in the database
    let settings = sqlx::query!(
        r#"
        INSERT INTO rosca_settings (rosca_id, notification_prefs, payout_rules, membership_rules_prefs, loan_prefs, logo_location, contacts, rosca_motto, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
        ON CONFLICT (rosca_id)
        DO UPDATE SET
            notification_prefs = COALESCE($2, rosca_settings.notification_prefs),
            payout_rules = COALESCE($3, rosca_settings.payout_rules),
            membership_rules_prefs = COALESCE($4, rosca_settings.membership_rules_prefs),
            loan_prefs = COALESCE($5, rosca_settings.loan_prefs),
            logo_location = COALESCE($6, rosca_settings.logo_location),
            contacts = COALESCE($7, rosca_settings.contacts),
            rosca_motto = COALESCE($8, rosca_settings.rosca_motto),
            updated_at = NOW()
        RETURNING rosca_id, notification_prefs, payout_rules, membership_rules_prefs, loan_prefs, logo_location, contacts, rosca_motto, updated_at
        "#,
        rosca_id,
        request.notification_prefs,
        request.payout_rules,
        request.membership_rules_prefs,
        request.loan_prefs,
        request.logo_location,
        request.contacts,
        request.rosca_motto
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error updating ROSCA settings: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    info!("ROSCA settings updated: rosca_id={}", rosca_id);
    Ok(Json(UpdateRoscaSettingsResponse {
        rosca_id: settings.rosca_id,
        notification_prefs: settings.notification_prefs,
        payout_rules: settings.payout_rules,
        membership_rules_prefs: settings.membership_rules_prefs,
        loan_prefs: settings.loan_prefs,
        logo_location: settings.logo_location,
        contacts: settings.contacts,
        rosca_motto: settings.rosca_motto,
        updated_at: settings.updated_at,
    }))
}

// Endpoint 61: GET /api/v1/roscas/:rosca_id/reports - Generate ROSCA reports
#[derive(Deserialize)]
struct ReportFilter {
    metric: Option<String>,
}

#[derive(Serialize)]
struct FinancialSummary {
    total_contributions: f64,
    total_payouts: f64,
    total_loans: f64,
    total_penalties: f64,
}

#[derive(Serialize)]
struct MemberParticipation {
    active_members: i64,
    total_contributions: i64,
    avg_contribution_per_member: f64,
    participation_rate: f64,
}

#[derive(Serialize)]
struct LoanStatus {
    total_loans: i64,
    total_disbursed: f64,
    total_repaid: f64,
    overdue_loans: i64,
}

#[derive(Serialize)]
#[serde(tag = "metric")]
enum ReportResponse {
    #[serde(rename = "financial_summary")]
    FinancialSummary { rosca_id: i32, data: FinancialSummary },
    #[serde(rename = "member_participation")]
    MemberParticipation { rosca_id: i32, data: MemberParticipation },
    #[serde(rename = "loan_status")]
    LoanStatus { rosca_id: i32, data: LoanStatus },
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
pub async fn get_rosca_reports(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path(rosca_id): Path<i32>,
    Query(filter): Query<ReportFilter>,
) -> Result<Json<ReportResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Generating report for rosca_id: {} by user_id: {}", rosca_id, auth_user.user_id);
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

    // Determine the report metric
    let metric = filter.metric.unwrap_or_else(|| "financial_summary".to_string());
    debug!("Generating {} report for rosca_id: {}", metric, rosca_id);

    match metric.as_str() {
        "financial_summary" => {
            let summary = sqlx::query!(
                r#"
                SELECT 
                    COALESCE((SELECT SUM(amount) FROM contributions WHERE rosca_id = $1 AND status = 'completed'), 0.0) AS total_contributions,
                    COALESCE((SELECT SUM(amount) FROM payouts WHERE rosca_id = $1), 0.0) AS total_payouts,
                    COALESCE((SELECT SUM(amount) FROM loans WHERE rosca_id = $1 AND disbursement_status = 'completed'), 0.0) AS total_loans,
                    COALESCE((SELECT SUM(amount) FROM contribution_penalties WHERE rosca_id = $1 AND status = 'applied'), 0.0) AS total_penalties
                "#,
                rosca_id
            )
            .fetch_one(&pool)
            .await
            .map_err(|e| { error!("Database error fetching financial summary: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

            info!("Financial summary generated for rosca_id: {}", rosca_id);
            Ok(Json(ReportResponse::FinancialSummary {
                rosca_id,
                data: FinancialSummary {
                    total_contributions: summary.total_contributions.unwrap_or(0.0),
                    total_payouts: summary.total_payouts.unwrap_or(0.0),
                    total_loans: summary.total_loans.unwrap_or(0.0),
                    total_penalties: summary.total_penalties.unwrap_or(0.0),
                },
            }))
        },
        "member_participation" => {
            let participation = sqlx::query!(
                r#"
                WITH contrib AS (
                    SELECT COUNT(*) AS total_contributions,
                           COUNT(DISTINCT user_id) AS active_users
                    FROM contributions
                    WHERE rosca_id = $1 AND status = 'completed'
                )
                SELECT 
                    (SELECT COUNT(*) FROM rosca_members WHERE rosca_id = $1 AND status = 'active') AS active_members,
                    COALESCE(c.total_contributions, 0) AS total_contributions,
                    COALESCE((SELECT AVG(amount) FROM contributions WHERE rosca_id = $1 AND status = 'completed'), 0.0) AS avg_contribution_per_member,
                    COALESCE(CAST(c.active_users AS FLOAT) / NULLIF((SELECT COUNT(*) FROM rosca_members WHERE rosca_id = $1 AND status = 'active'), 0), 0.0) AS participation_rate
                FROM contrib c
                "#,
                rosca_id
            )
            .fetch_one(&pool)
            .await
            .map_err(|e| { error!("Database error fetching member participation: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

            info!("Member participation report generated for rosca_id: {}", rosca_id);
            Ok(Json(ReportResponse::MemberParticipation {
                rosca_id,
                data: MemberParticipation {
                    active_members: participation.active_members.unwrap_or(0),
                    total_contributions: participation.total_contributions.unwrap_or(0),
                    avg_contribution_per_member: participation.avg_contribution_per_member.unwrap_or(0.0),
                    participation_rate: participation.participation_rate.unwrap_or(0.0),
                },
            }))
        },
        "loan_status" => {
            let status = sqlx::query!(
                r#"
                SELECT 
                    COUNT(*) AS total_loans,
                    COALESCE(SUM(amount), 0.0) AS total_disbursed,
                    COALESCE((SELECT SUM(lr.amount + lr.interest_amount) FROM loan_repayments lr WHERE lr.loan_id IN (SELECT loan_id FROM loans WHERE rosca_id = $1)), 0.0) AS total_repaid,
                    COUNT(CASE WHEN status = 'active' AND NOW() > disbursed_at + INTERVAL '30 days' THEN 1 END) AS overdue_loans
                FROM loans
                WHERE rosca_id = $1 AND disbursement_status = 'completed'
                "#,
                rosca_id
            )
            .fetch_one(&pool)
            .await
            .map_err(|e| { error!("Database error fetching loan status: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

            info!("Loan status report generated for rosca_id: {}", rosca_id);
            Ok(Json(ReportResponse::LoanStatus {
                rosca_id,
                data: LoanStatus {
                    total_loans: status.total_loans,
                    total_disbursed: status.total_disbursed.unwrap_or(0.0),
                    total_repaid: status.total_repaid.unwrap_or(0.0),
                    overdue_loans: status.overdue_loans.unwrap_or(0),
                },
            }))
        },
        _ => {
            error!("Invalid metric: {}", metric);
            Err((StatusCode::BAD_REQUEST, "Invalid metric".to_string()))
        },
    }
}

// Endpoint 63: GET /api/v1/roscas/:rosca_id/export - Export ROSCA data
#[derive(Deserialize, Default)]
struct ExportFilter {
    data_type: Option<String>,
    format: Option<String>,
    start_time: Option<DateTime<Utc>>,
    end_time: Option<DateTime<Utc>>,
    cycle_number: Option<i32>,
}

#[derive(Serialize)]
struct ContributionExport {
    contribution_id: i32,
    rosca_name: String,
    username: String,
    amount: f64,
    cycle_number: i32,
    status: String,
    paid_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
struct LoanExport {
    loan_id: i32,
    rosca_name: String, 
    username: String,
    amount: f64,
    interest_rate: f64,
    status: String,
    disbursed_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
struct PayoutExport {
    payout_id: i32,
    rosca_name: String, 
    username: String,
    amount: f64,
    cycle_number: i32,
    payout_status: String,
    payout_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
struct MemberExport {
    user_id: i32,          
    rosca_name: String, 
    username: String,
    status: String,
    member_type: String,
    joined_at: Option<DateTime<Utc>>,
}

#[derive(sqlx::FromRow)]
struct RoscaSettings {
    logo_location: Option<String>,
    contacts: Option<String>,
    rosca_motto: Option<String>,
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
pub async fn export_rosca_data(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path(rosca_id): Path<i32>,
    Query(filter): Query<ExportFilter>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Exporting data for rosca_id: {} by user_id: {}", rosca_id, auth_user.user_id);
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

    // Fetch ROSCA settings for PDF export (includes rosca_name implicitly via rosca_id)
    let settings = sqlx::query_as::<_, RoscaSettings>(
        "SELECT logo_location, contacts, rosca_motto FROM rosca_settings WHERE rosca_id = $1",
    )
    .bind(rosca_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error fetching settings: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    let (logo_location, contacts, rosca_motto) = settings.map_or(
        (None, None, None),
        |s| (s.logo_location, s.contacts, s.rosca_motto),
    );

    // Determine export parameters
    let data_type = filter.data_type.unwrap_or_else(|| "contributions".to_string());
    let format = filter.format.unwrap_or_else(|| "json".to_string());
    let valid_data_types = vec!["contributions", "loans", "payouts", "members"];
    let valid_formats = vec!["pdf", "csv", "excel", "json"];

    if !valid_data_types.contains(&data_type.as_str()) || !valid_formats.contains(&format.as_str()) {
        error!("Invalid parameters: data_type={}, format={}", data_type, format);
        return Err((StatusCode::BAD_REQUEST, "Invalid export parameters".to_string()));
    }

    // Fetch rosca_name for inclusion in export
    let rosca_name = sqlx::query_scalar!(
        "SELECT name FROM roscas WHERE rosca_id = $1",
        rosca_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error fetching rosca_name: {}", e); (StatusCode::NOT_FOUND, "ROSCA not found".to_string()) })?;

    // Build query conditions
    let mut conditions = vec!["c.rosca_id = $1"];
    let mut params: Vec<&(dyn sqlx::Encode<'_, sqlx::Postgres> + sqlx::Type<sqlx::Postgres> + Sync)> = vec![&rosca_id];
    let mut param_index = 2;

    if let Some(start_time) = filter.start_time {
        conditions.push(format!("timestamp_field >= ${}", param_index));
        params.push(&start_time);
        param_index += 1;
    }
    if let Some(end_time) = filter.end_time {
        conditions.push(format!("timestamp_field <= ${}", param_index));
        params.push(&end_time);
        param_index += 1;
    }
    if let Some(cycle_number) = filter.cycle_number {
        conditions.push(format!("cycle_number = ${}", param_index));
        params.push(&cycle_number);
        param_index += 1;
    }

    let where_clause = if conditions.is_empty() { String::new() } else { format!("WHERE {}", conditions.join(" AND ")) };
    let mut headers = HeaderMap::new();
    let filename = format!("rosca_{}_{}_{}.{}", rosca_id, data_type, Utc::now().format("%Y%m%d_%H%M%S"), format);
    headers.insert("Content-Disposition", HeaderValue::from_str(&format!("attachment; filename=\"{}\"", filename)).unwrap());

    match data_type.as_str() {
        "contributions" => {
            let query = format!(
                "SELECT c.contribution_id, r.name AS rosca_name, u.username, c.amount, c.cycle_number, c.status, c.paid_at AS timestamp_field
                 FROM contributions c 
                 JOIN users u ON c.user_id = u.user_id 
                 JOIN roscas r ON c.rosca_id = r.rosca_id 
                 {} ORDER BY c.paid_at DESC",
                where_clause.replace("timestamp_field", "paid_at")
            );
            let data = sqlx::query_as_with::<_, ContributionExport, _>(&query, params)
                .fetch_all(&pool)
                .await
                .map_err(|e| { error!("Database error fetching contributions: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

            match format.as_str() {
                "json" => {
                    headers.insert("Content-Type", HeaderValue::from_static("application/json"));
                    Ok((headers, Json(data)).into_response())
                },
                "csv" => {
                    headers.insert("Content-Type", HeaderValue::from_static("text/csv"));
                    let mut csv_data = String::from("contribution_id,rosca_name,username,amount,cycle_number,status,paid_at\n");
                    for item in data {
                        csv_data.push_str(&format!(
                            "{},{},{},{},{},{},{}\n",
                            item.contribution_id, item.rosca_name, item.username, item.amount, item.cycle_number, item.status,
                            item.paid_at.map_or("".to_string(), |d| d.to_rfc3339())
                        ));
                    }
                    Ok((headers, csv_data).into_response())
                },
                "excel" => {
                    headers.insert("Content-Type", HeaderValue::from_static("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"));
                    let mut workbook = Workbook::new();
                    let worksheet = workbook.add_worksheet();
                    worksheet.write_string(0, 0, "Contribution ID").unwrap();
                    worksheet.write_string(0, 1, "ROSCA Name").unwrap();
                    worksheet.write_string(0, 2, "Username").unwrap();
                    worksheet.write_string(0, 3, "Amount").unwrap();
                    worksheet.write_string(0, 4, "Cycle Number").unwrap();
                    worksheet.write_string(0, 5, "Status").unwrap();
                    worksheet.write_string(0, 6, "Paid At").unwrap();

                    for (i, item) in data.iter().enumerate() {
                        let row = (i + 1) as u32;
                        worksheet.write_number(row, 0, item.contribution_id as f64).unwrap();
                        worksheet.write_string(row, 1, &item.rosca_name).unwrap();
                        worksheet.write_string(row, 2, &item.username).unwrap();
                        worksheet.write_number(row, 3, item.amount).unwrap();
                        worksheet.write_number(row, 4, item.cycle_number as f64).unwrap();
                        worksheet.write_string(row, 5, &item.status).unwrap();
                        worksheet.write_string(row, 6, &item.paid_at.map_or("".to_string(), |d| d.to_rfc3339())).unwrap();
                    }

                    let buf = workbook.save_to_buffer().unwrap();
                    Ok((headers, buf).into_response())
                },
                "pdf" => {
                    headers.insert("Content-Type", HeaderValue::from_static("application/pdf"));
                    let (mut doc, page1, layer1) = PdfDocument::new(&filename, Mm(210.0), Mm(297.0), "Layer 1");
                    let font = doc.add_builtin_font(BuiltinFont::Helvetica).unwrap();
                    let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold).unwrap();
                    let mut current_page = page1;
                    let mut current_layer = layer1;
                    let mut current_y = Mm(260.0);
                    let margin = Mm(10.0);
                    let row_height = Mm(10.0);
                    let col_width = Mm(30.0);

                    doc = doc.with_producer("xAI ROSCA Export");
                    let headers = ["ID", "ROSCA Name", "User", "Amount", "Cycle", "Status", "Paid At"];
                    let draw_page_content = |doc: &mut PdfDocumentReference, page: PdfPageIndex, layer: PdfLayerIndex| {
                        let layer = doc.get_page(page).get_layer(layer);
                        if let Some(ref motto) = rosca_motto {
                            layer.use_text(motto, 8.0, Mm(margin), Mm(margin), &font);
                        }
                    };

                    draw_page_content(&mut doc, current_page, current_layer);
                    for (col, header) in headers.iter().enumerate() {
                        doc.get_page(current_page).get_layer(current_layer).use_text(
                            header, 10.0, Mm(margin + col as f32 * col_width), current_y, &font_bold
                        );
                    }
                    current_y -= row_height;

                    for item in data {
                        if current_y < margin + row_height {
                            let (new_page, new_layer) = doc.add_page(Mm(210.0), Mm(297.0), "Layer 1");
                            current_page = new_page;
                            current_layer = new_layer;
                            current_y = Mm(260.0);
                            draw_page_content(&mut doc, current_page, current_layer);
                            for (col, header) in headers.iter().enumerate() {
                                doc.get_page(current_page).get_layer(current_layer).use_text(
                                    header, 10.0, Mm(margin + col as f32 * col_width), current_y, &font_bold
                                );
                            }
                            current_y -= row_height;
                        }

                        let layer = doc.get_page(current_page).get_layer(current_layer);
                        let truncate = |text: &str, width: f32| {
                            let mut truncated = text.to_string();
                            let mut text_width = font.text_width(&truncated, 10.0);
                            while text_width > width && !truncated.is_empty() {
                                truncated.pop();
                                text_width = font.text_width(&truncated, 10.0);
                            }
                            if truncated.len() < text.len() { truncated.push_str("..."); }
                            truncated
                        };
                        layer.use_text(truncate(&item.contribution_id.to_string(), col_width.into()), 10.0, Mm(margin), current_y, &font);
                        layer.use_text(truncate(&item.rosca_name, col_width.into()), 10.0, Mm(margin + col_width), current_y, &font);
                        layer.use_text(truncate(&item.username, col_width.into()), 10.0, Mm(margin + 2.0 * col_width), current_y, &font);
                        layer.use_text(truncate(&item.amount.to_string(), col_width.into()), 10.0, Mm(margin + 3.0 * col_width), current_y, &font);
                        layer.use_text(truncate(&item.cycle_number.to_string(), col_width.into()), 10.0, Mm(margin + 4.0 * col_width), current_y, &font);
                        layer.use_text(truncate(&item.status, col_width.into()), 10.0, Mm(margin + 5.0 * col_width), current_y, &font);
                        layer.use_text(truncate(&item.paid_at.map_or("".to_string(), |d| d.to_rfc3339()), Mm(40.0).into()), 10.0, Mm(margin + 6.0 * col_width), current_y, &font);
                        current_y -= row_height;
                    }

                    let pdf_data = doc.save_to_bytes().unwrap();
                    Ok((headers, pdf_data).into_response())
                },
                _ => unreachable!(), // Valid formats already checked
            }
        },
        "loans" => {
            let query = format!(
                "SELECT l.loan_id, r.name AS rosca_name, u.username, l.amount, l.interest_rate, l.status, l.disbursed_at AS timestamp_field
                 FROM loans l 
                 JOIN users u ON l.user_id = u.user_id 
                 JOIN roscas r ON l.rosca_id = r.rosca_id 
                 {} ORDER BY l.created_at DESC",
                where_clause.replace("timestamp_field", "disbursed_at")
            );
            let data = sqlx::query_as_with::<_, LoanExport, _>(&query, params)
                .fetch_all(&pool)
                .await
                .map_err(|e| { error!("Database error fetching loans: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

            match format.as_str() {
                "json" => {
                    headers.insert("Content-Type", HeaderValue::from_static("application/json"));
                    Ok((headers, Json(data)).into_response())
                },
                "csv" => {
                    headers.insert("Content-Type", HeaderValue::from_static("text/csv"));
                    let mut csv_data = String::from("loan_id,rosca_name,username,amount,interest_rate,status,disbursed_at\n");
                    for item in data {
                        csv_data.push_str(&format!(
                            "{},{},{},{},{},{},{}\n",
                            item.loan_id, item.rosca_name, item.username, item.amount, item.interest_rate, item.status,
                            item.disbursed_at.map_or("".to_string(), |d| d.to_rfc3339())
                        ));
                    }
                    Ok((headers, csv_data).into_response())
                },
                "excel" => {
                    headers.insert("Content-Type", HeaderValue::from_static("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"));
                    let mut workbook = Workbook::new();
                    let worksheet = workbook.add_worksheet();
                    worksheet.write_string(0, 0, "Loan ID").unwrap();
                    worksheet.write_string(0, 1, "ROSCA Name").unwrap();
                    worksheet.write_string(0, 2, "Username").unwrap();
                    worksheet.write_string(0, 3, "Amount").unwrap();
                    worksheet.write_string(0, 4, "Interest Rate").unwrap();
                    worksheet.write_string(0, 5, "Status").unwrap();
                    worksheet.write_string(0, 6, "Disbursed At").unwrap();

                    for (i, item) in data.iter().enumerate() {
                        let row = (i + 1) as u32;
                        worksheet.write_number(row, 0, item.loan_id as f64).unwrap();
                        worksheet.write_string(row, 1, &item.rosca_name).unwrap();
                        worksheet.write_string(row, 2, &item.username).unwrap();
                        worksheet.write_number(row, 3, item.amount).unwrap();
                        worksheet.write_number(row, 4, item.interest_rate).unwrap();
                        worksheet.write_string(row, 5, &item.status).unwrap();
                        worksheet.write_string(row, 6, &item.disbursed_at.map_or("".to_string(), |d| d.to_rfc3339())).unwrap();
                    }

                    let buf = workbook.save_to_buffer().unwrap();
                    Ok((headers, buf).into_response())
                },
                "pdf" => {
                    headers.insert("Content-Type", HeaderValue::from_static("application/pdf"));
                    let (mut doc, page1, layer1) = PdfDocument::new(&filename, Mm(210.0), Mm(297.0), "Layer 1");
                    let font = doc.add_builtin_font(BuiltinFont::Helvetica).unwrap();
                    let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold).unwrap();
                    let mut current_page = page1;
                    let mut current_layer = layer1;
                    let mut current_y = Mm(260.0);
                    let margin = Mm(10.0);
                    let row_height = Mm(10.0);
                    let col_width = Mm(30.0);

                    doc = doc.with_producer("xAI ROSCA Export");
                    let headers = ["ID", "ROSCA Name", "User", "Amount", "Interest", "Status", "Disbursed At"];
                    let draw_page_content = |doc: &mut PdfDocumentReference, page: PdfPageIndex, layer: PdfLayerIndex| {
                        let layer = doc.get_page(page).get_layer(layer);
                        if let Some(ref motto) = rosca_motto {
                            layer.use_text(motto, 8.0, Mm(margin), Mm(margin), &font);
                        }
                    };

                    draw_page_content(&mut doc, current_page, current_layer);
                    for (col, header) in headers.iter().enumerate() {
                        doc.get_page(current_page).get_layer(current_layer).use_text(
                            header, 10.0, Mm(margin + col as f32 * col_width), current_y, &font_bold
                        );
                    }
                    current_y -= row_height;

                    for item in data {
                        if current_y < margin + row_height {
                            let (new_page, new_layer) = doc.add_page(Mm(210.0), Mm(297.0), "Layer 1");
                            current_page = new_page;
                            current_layer = new_layer;
                            current_y = Mm(260.0);
                            draw_page_content(&mut doc, current_page, current_layer);
                            for (col, header) in headers.iter().enumerate() {
                                doc.get_page(current_page).get_layer(current_layer).use_text(
                                    header, 10.0, Mm(margin + col as f32 * col_width), current_y, &font_bold
                                );
                            }
                            current_y -= row_height;
                        }

                        let layer = doc.get_page(current_page).get_layer(current_layer);
                        let truncate = |text: &str, width: f32| {
                            let mut truncated = text.to_string();
                            let mut text_width = font.text_width(&truncated, 10.0);
                            while text_width > width && !truncated.is_empty() {
                                truncated.pop();
                                text_width = font.text_width(&truncated, 10.0);
                            }
                            if truncated.len() < text.len() { truncated.push_str("..."); }
                            truncated
                        };
                        layer.use_text(truncate(&item.loan_id.to_string(), col_width.into()), 10.0, Mm(margin), current_y, &font);
                        layer.use_text(truncate(&item.rosca_name, col_width.into()), 10.0, Mm(margin + col_width), current_y, &font);
                        layer.use_text(truncate(&item.username, col_width.into()), 10.0, Mm(margin + 2.0 * col_width), current_y, &font);
                        layer.use_text(truncate(&item.amount.to_string(), col_width.into()), 10.0, Mm(margin + 3.0 * col_width), current_y, &font);
                        layer.use_text(truncate(&item.interest_rate.to_string(), col_width.into()), 10.0, Mm(margin + 4.0 * col_width), current_y, &font);
                        layer.use_text(truncate(&item.status, col_width.into()), 10.0, Mm(margin + 5.0 * col_width), current_y, &font);
                        layer.use_text(truncate(&item.disbursed_at.map_or("".to_string(), |d| d.to_rfc3339()), Mm(40.0).into()), 10.0, Mm(margin + 6.0 * col_width), current_y, &font);
                        current_y -= row_height;
                    }

                    let pdf_data = doc.save_to_bytes().unwrap();
                    Ok((headers, pdf_data).into_response())
                },
                _ => unreachable!(),
            }
        },
        "payouts" => {
            let query = format!(
                "SELECT p.payout_id, r.name AS rosca_name, u.username, p.amount, p.cycle_number, p.payout_status, p.payout_at AS timestamp_field
                 FROM payouts p 
                 JOIN users u ON p.user_id = u.user_id 
                 JOIN roscas r ON p.rosca_id = r.rosca_id 
                 {} ORDER BY p.created_at DESC",
                where_clause.replace("timestamp_field", "payout_at")
            );
            let data = sqlx::query_as_with::<_, PayoutExport, _>(&query, params)
                .fetch_all(&pool)
                .await
                .map_err(|e| { error!("Database error fetching payouts: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

            match format.as_str() {
                "json" => {
                    headers.insert("Content-Type", HeaderValue::from_static("application/json"));
                    Ok((headers, Json(data)).into_response())
                },
                "csv" => {
                    headers.insert("Content-Type", HeaderValue::from_static("text/csv"));
                    let mut csv_data = String::from("payout_id,rosca_name,username,amount,cycle_number,payout_status,payout_at\n");
                    for item in data {
                        csv_data.push_str(&format!(
                            "{},{},{},{},{},{},{}\n",
                            item.payout_id, item.rosca_name, item.username, item.amount, item.cycle_number, item.payout_status,
                            item.payout_at.map_or("".to_string(), |d| d.to_rfc3339())
                        ));
                    }
                    Ok((headers, csv_data).into_response())
                },
                "excel" => {
                    headers.insert("Content-Type", HeaderValue::from_static("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"));
                    let mut workbook = Workbook::new();
                    let worksheet = workbook.add_worksheet();
                    worksheet.write_string(0, 0, "Payout ID").unwrap();
                    worksheet.write_string(0, 1, "ROSCA Name").unwrap();
                    worksheet.write_string(0, 2, "Username").unwrap();
                    worksheet.write_string(0, 3, "Amount").unwrap();
                    worksheet.write_string(0, 4, "Cycle Number").unwrap();
                    worksheet.write_string(0, 5, "Payout Status").unwrap();
                    worksheet.write_string(0, 6, "Payout At").unwrap();

                    for (i, item) in data.iter().enumerate() {
                        let row = (i + 1) as u32;
                        worksheet.write_number(row, 0, item.payout_id as f64).unwrap();
                        worksheet.write_string(row, 1, &item.rosca_name).unwrap();
                        worksheet.write_string(row, 2, &item.username).unwrap();
                        worksheet.write_number(row, 3, item.amount).unwrap();
                        worksheet.write_number(row, 4, item.cycle_number as f64).unwrap();
                        worksheet.write_string(row, 5, &item.payout_status).unwrap();
                        worksheet.write_string(row, 6, &item.payout_at.map_or("".to_string(), |d| d.to_rfc3339())).unwrap();
                    }

                    let buf = workbook.save_to_buffer().unwrap();
                    Ok((headers, buf).into_response())
                },
                "pdf" => {
                    headers.insert("Content-Type", HeaderValue::from_static("application/pdf"));
                    let (mut doc, page1, layer1) = PdfDocument::new(&filename, Mm(210.0), Mm(297.0), "Layer 1");
                    let font = doc.add_builtin_font(BuiltinFont::Helvetica).unwrap();
                    let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold).unwrap();
                    let mut current_page = page1;
                    let mut current_layer = layer1;
                    let mut current_y = Mm(260.0);
                    let margin = Mm(10.0);
                    let row_height = Mm(10.0);
                    let col_width = Mm(30.0);

                    doc = doc.with_producer("xAI ROSCA Export");
                    let headers = ["ID", "ROSCA Name", "User", "Amount", "Cycle", "Status", "Payout At"];
                    let draw_page_content = |doc: &mut PdfDocumentReference, page: PdfPageIndex, layer: PdfLayerIndex| {
                        let layer = doc.get_page(page).get_layer(layer);
                        if let Some(ref motto) = rosca_motto {
                            layer.use_text(motto, 8.0, Mm(margin), Mm(margin), &font);
                        }
                    };

                    draw_page_content(&mut doc, current_page, current_layer);
                    for (col, header) in headers.iter().enumerate() {
                        doc.get_page(current_page).get_layer(current_layer).use_text(
                            header, 10.0, Mm(margin + col as f32 * col_width), current_y, &font_bold
                        );
                    }
                    current_y -= row_height;

                    for item in data {
                        if current_y < margin + row_height {
                            let (new_page, new_layer) = doc.add_page(Mm(210.0), Mm(297.0), "Layer 1");
                            current_page = new_page;
                            current_layer = new_layer;
                            current_y = Mm(260.0);
                            draw_page_content(&mut doc, current_page, current_layer);
                            for (col, header) in headers.iter().enumerate() {
                                doc.get_page(current_page).get_layer(current_layer).use_text(
                                    header, 10.0, Mm(margin + col as f32 * col_width), current_y, &font_bold
                                );
                            }
                            current_y -= row_height;
                        }

                        let layer = doc.get_page(current_page).get_layer(current_layer);
                        let truncate = |text: &str, width: f32| {
                            let mut truncated = text.to_string();
                            let mut text_width = font.text_width(&truncated, 10.0);
                            while text_width > width && !truncated.is_empty() {
                                truncated.pop();
                                text_width = font.text_width(&truncated, 10.0);
                            }
                            if truncated.len() < text.len() { truncated.push_str("..."); }
                            truncated
                        };
                        layer.use_text(truncate(&item.payout_id.to_string(), col_width.into()), 10.0, Mm(margin), current_y, &font);
                        layer.use_text(truncate(&item.rosca_name, col_width.into()), 10.0, Mm(margin + col_width), current_y, &font);
                        layer.use_text(truncate(&item.username, col_width.into()), 10.0, Mm(margin + 2.0 * col_width), current_y, &font);
                        layer.use_text(truncate(&item.amount.to_string(), col_width.into()), 10.0, Mm(margin + 3.0 * col_width), current_y, &font);
                        layer.use_text(truncate(&item.cycle_number.to_string(), col_width.into()), 10.0, Mm(margin + 4.0 * col_width), current_y, &font);
                        layer.use_text(truncate(&item.payout_status, col_width.into()), 10.0, Mm(margin + 5.0 * col_width), current_y, &font);
                        layer.use_text(truncate(&item.payout_at.map_or("".to_string(), |d| d.to_rfc3339()), Mm(40.0).into()), 10.0, Mm(margin + 6.0 * col_width), current_y, &font);
                        current_y -= row_height;
                    }

                    let pdf_data = doc.save_to_bytes().unwrap();
                    Ok((headers, pdf_data).into_response())
                },
                _ => unreachable!(),
            }
        },
        "members" => {
            let query = format!(
                "SELECT rm.user_id AS user_id, r.name AS rosca_name, u.username, rm.status, rm.member_type, rm.joined_at AS timestamp_field
                 FROM rosca_members rm 
                 JOIN users u ON rm.user_id = u.user_id 
                 JOIN roscas r ON rm.rosca_id = r.rosca_id 
                 {} ORDER BY rm.joined_at DESC",
                where_clause.replace("timestamp_field", "joined_at").replace("cycle_number", "1=1")
            );
            let data = sqlx::query_as_with::<_, MemberExport, _>(&query, params)
                .fetch_all(&pool)
                .await
                .map_err(|e| { error!("Database error fetching members: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

            match format.as_str() {
                "json" => {
                    headers.insert("Content-Type", HeaderValue::from_static("application/json"));
                    Ok((headers, Json(data)).into_response())
                },
                "csv" => {
                    headers.insert("Content-Type", HeaderValue::from_static("text/csv"));
                    let mut csv_data = String::from("user_id,rosca_name,username,status,member_type,joined_at\n");
                    for item in data {
                        csv_data.push_str(&format!(
                            "{},{},{},{},{},{}\n",
                            item.user_id, item.rosca_name, item.username, item.status, item.member_type,
                            item.joined_at.map_or("".to_string(), |d| d.to_rfc3339())
                        ));
                    }
                    Ok((headers, csv_data).into_response())
                },
                "excel" => {
                    headers.insert("Content-Type", HeaderValue::from_static("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"));
                    let mut workbook = Workbook::new();
                    let worksheet = workbook.add_worksheet();
                    worksheet.write_string(0, 0, "User ID").unwrap();
                    worksheet.write_string(0, 1, "ROSCA Name").unwrap();
                    worksheet.write_string(0, 2, "Username").unwrap();
                    worksheet.write_string(0, 3, "Status").unwrap();
                    worksheet.write_string(0, 4, "Member Type").unwrap();
                    worksheet.write_string(0, 5, "Joined At").unwrap();

                    for (i, item) in data.iter().enumerate() {
                        let row = (i + 1) as u32;
                        worksheet.write_number(row, 0, item.user_id as f64).unwrap();
                        worksheet.write_string(row, 1, &item.rosca_name).unwrap();
                        worksheet.write_string(row, 2, &item.username).unwrap();
                        worksheet.write_string(row, 3, &item.status).unwrap();
                        worksheet.write_string(row, 4, &item.member_type).unwrap();
                        worksheet.write_string(row, 5, &item.joined_at.map_or("".to_string(), |d| d.to_rfc3339())).unwrap();
                    }

                    let buf = workbook.save_to_buffer().unwrap();
                    Ok((headers, buf).into_response())
                },
                "pdf" => {
                    headers.insert("Content-Type", HeaderValue::from_static("application/pdf"));
                    let (mut doc, page1, layer1) = PdfDocument::new(&filename, Mm(210.0), Mm(297.0), "Layer 1");
                    let font = doc.add_builtin_font(BuiltinFont::Helvetica).unwrap();
                    let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold).unwrap();
                    let mut current_page = page1;
                    let mut current_layer = layer1;
                    let mut current_y = Mm(260.0);
                    let margin = Mm(10.0);
                    let row_height = Mm(10.0);
                    let col_width = Mm(35.0);

                    doc = doc.with_producer("xAI ROSCA Export");
                    let headers = ["User ID", "ROSCA Name", "Username", "Status", "Type", "Joined At"];
                    let draw_page_content = |doc: &mut PdfDocumentReference, page: PdfPageIndex, layer: PdfLayerIndex| {
                        let layer = doc.get_page(page).get_layer(layer);
                        if let Some(ref motto) = rosca_motto {
                            layer.use_text(motto, 8.0, Mm(margin), Mm(margin), &font);
                        }
                    };

                    draw_page_content(&mut doc, current_page, current_layer);
                    for (col, header) in headers.iter().enumerate() {
                        doc.get_page(current_page).get_layer(current_layer).use_text(
                            header, 10.0, Mm(margin + col as f32 * col_width), current_y, &font_bold
                        );
                    }
                    current_y -= row_height;

                    for item in data {
                        if current_y < margin + row_height {
                            let (new_page, new_layer) = doc.add_page(Mm(210.0), Mm(297.0), "Layer 1");
                            current_page = new_page;
                            current_layer = new_layer;
                            current_y = Mm(260.0);
                            draw_page_content(&mut doc, current_page, current_layer);
                            for (col, header) in headers.iter().enumerate() {
                                doc.get_page(current_page).get_layer(current_layer).use_text(
                                    header, 10.0, Mm(margin + col as f32 * col_width), current_y, &font_bold
                                );
                            }
                            current_y -= row_height;
                        }

                        let layer = doc.get_page(current_page).get_layer(current_layer);
                        let truncate = |text: &str, width: f32| {
                            let mut truncated = text.to_string();
                            let mut text_width = font.text_width(&truncated, 10.0);
                            while text_width > width && !truncated.is_empty() {
                                truncated.pop();
                                text_width = font.text_width(&truncated, 10.0);
                            }
                            if truncated.len() < text.len() { truncated.push_str("..."); }
                            truncated
                        };
                        layer.use_text(truncate(&item.user_id.to_string(), col_width.into()), 10.0, Mm(margin), current_y, &font);
                        layer.use_text(truncate(&item.rosca_name, col_width.into()), 10.0, Mm(margin + col_width), current_y, &font);
                        layer.use_text(truncate(&item.username, col_width.into()), 10.0, Mm(margin + 2.0 * col_width), current_y, &font);
                        layer.use_text(truncate(&item.status, col_width.into()), 10.0, Mm(margin + 3.0 * col_width), current_y, &font);
                        layer.use_text(truncate(&item.member_type, col_width.into()), 10.0, Mm(margin + 4.0 * col_width), current_y, &font);
                        layer.use_text(truncate(&item.joined_at.map_or("".to_string(), |d| d.to_rfc3339()), Mm(35.0).into()), 10.0, Mm(margin + 5.0 * col_width), current_y, &font);
                        current_y -= row_height;
                    }

                    let pdf_data = doc.save_to_bytes().unwrap();
                    Ok((headers, pdf_data).into_response())
                },
                _ => unreachable!(),
            }
        },
        _ => unreachable!(), // Valid data types already checked
    }
}

// Endpoint 65: POST /api/v1/roscas/:rosca_id/import - Import ROSCA data
#[derive(Deserialize)]
struct ImportRequest {
    data_type: String,
    format: String,
    data: String,
}

#[derive(Serialize)]
struct ImportResponse {
    rosca_id: i32,
    records_imported: i64,
    message: String,
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
pub async fn import_rosca_data(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path(rosca_id): Path<i32>,
    Json(request): Json<ImportRequest>,
) -> Result<Json<ImportResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Importing data for rosca_id: {} by user_id: {}", rosca_id, auth_user.user_id);
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

    // Validate import parameters
    let valid_data_types = vec!["contributions", "loans", "payouts", "members"];
    let valid_formats = vec!["csv", "json"];
    if !valid_data_types.contains(&request.data_type.as_str()) || !valid_formats.contains(&request.format.as_str()) {
        error!("Invalid parameters: data_type={}, format={}", request.data_type, request.format);
        return Err((StatusCode::BAD_REQUEST, "Invalid data type or format".to_string()));
    }

    let mut records_imported = 0;

    match (request.data_type.as_str(), request.format.as_str()) {
        ("contributions", "csv") => {
            let mut rdr = csv::Reader::from_reader(request.data.as_bytes());
            let headers = rdr.headers()
                .map_err(|e| { error!("Failed to read CSV headers: {}", e); (StatusCode::BAD_REQUEST, "Invalid CSV format".to_string()) })?
                .clone();
            if !headers.iter().eq(vec!["contribution_id", "rosca_name", "username", "amount", "cycle_number", "status", "paid_at"].iter()) {
                error!("Invalid CSV headers: {:?}", headers);
                return Err((StatusCode::BAD_REQUEST, "Invalid CSV headers".to_string()));
            }

            for result in rdr.records() {
                let record = result.map_err(|e| { error!("CSV parsing error: {}", e); (StatusCode::BAD_REQUEST, "Invalid CSV data".to_string()) })?;
                let username = &record[2];
                let amount: f64 = record[3].parse().map_err(|e| { error!("Invalid amount: {}", e); (StatusCode::BAD_REQUEST, "Invalid amount".to_string()) })?;
                let cycle_number: i32 = record[4].parse().map_err(|e| { error!("Invalid cycle_number: {}", e); (StatusCode::BAD_REQUEST, "Invalid cycle number".to_string()) })?;
                let status = &record[5];
                let paid_at = if record[6].is_empty() {
                    None
                } else {
                    Some(DateTime::parse_from_rfc3339(&record[6])
                        .map(|dt| dt.with_timezone(&Utc))
                        .map_err(|e| { error!("Invalid paid_at: {}", e); (StatusCode::BAD_REQUEST, "Invalid paid_at format".to_string()) })?)
                };

                let user_id = sqlx::query_scalar!(
                    "SELECT user_id FROM users WHERE username = $1",
                    username
                )
                .fetch_one(&pool)
                .await
                .map_err(|e| { error!("User not found: {}", e); (StatusCode::BAD_REQUEST, "User not found".to_string()) })?;

                sqlx::query!(
                    "INSERT INTO contributions (rosca_id, user_id, amount, cycle_number, status, paid_at)
                     VALUES ($1, $2, $3, $4, $5, $6)
                     ON CONFLICT (contribution_id) DO NOTHING",
                    rosca_id,
                    user_id,
                    amount,
                    cycle_number,
                    status,
                    paid_at
                )
                .execute(&pool)
                .await
                .map_err(|e| { error!("Database error importing contribution: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

                records_imported += 1;
            }
        },
        ("contributions", "json") => {
            let records: Vec<serde_json::Value> = serde_json::from_str(&request.data)
                .map_err(|e| { error!("JSON parsing error: {}", e); (StatusCode::BAD_REQUEST, "Invalid JSON data".to_string()) })?;

            for record in records {
                let username = record["username"].as_str()
                    .ok_or_else(|| { error!("Missing username in JSON"); (StatusCode::BAD_REQUEST, "Missing username".to_string()) })?;
                let amount = record["amount"].as_f64()
                    .ok_or_else(|| { error!("Missing or invalid amount in JSON"); (StatusCode::BAD_REQUEST, "Invalid amount".to_string()) })?;
                let cycle_number = record["cycle_number"].as_i64()
                    .ok_or_else(|| { error!("Missing or invalid cycle_number in JSON"); (StatusCode::BAD_REQUEST, "Invalid cycle number".to_string()) })? as i32;
                let status = record["status"].as_str()
                    .ok_or_else(|| { error!("Missing status in JSON"); (StatusCode::BAD_REQUEST, "Missing status".to_string()) })?;
                let paid_at = record["paid_at"].as_str().map(|s| {
                    DateTime::parse_from_rfc3339(s)
                        .map(|dt| dt.with_timezone(&Utc))
                        .map_err(|e| { error!("Invalid paid_at: {}", e); (StatusCode::BAD_REQUEST, "Invalid paid_at format".to_string()) })
                }).transpose()?;

                let user_id = sqlx::query_scalar!(
                    "SELECT user_id FROM users WHERE username = $1",
                    username
                )
                .fetch_one(&pool)
                .await
                .map_err(|e| { error!("User not found: {}", e); (StatusCode::BAD_REQUEST, "User not found".to_string()) })?;

                sqlx::query!(
                    "INSERT INTO contributions (rosca_id, user_id, amount, cycle_number, status, paid_at)
                     VALUES ($1, $2, $3, $4, $5, $6)
                     ON CONFLICT (contribution_id) DO NOTHING",
                    rosca_id,
                    user_id,
                    amount,
                    cycle_number,
                    status,
                    paid_at
                )
                .execute(&pool)
                .await
                .map_err(|e| { error!("Database error importing contribution: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

                records_imported += 1;
            }
        },
        ("loans", "csv") => {
            let mut rdr = csv::Reader::from_reader(request.data.as_bytes());
            let headers = rdr.headers()
                .map_err(|e| { error!("Failed to read CSV headers: {}", e); (StatusCode::BAD_REQUEST, "Invalid CSV format".to_string()) })?
                .clone();
            if !headers.iter().eq(vec!["loan_id", "rosca_name", "username", "amount", "interest_rate", "status", "disbursed_at"].iter()) {
                error!("Invalid CSV headers: {:?}", headers);
                return Err((StatusCode::BAD_REQUEST, "Invalid CSV headers".to_string()));
            }

            for result in rdr.records() {
                let record = result.map_err(|e| { error!("CSV parsing error: {}", e); (StatusCode::BAD_REQUEST, "Invalid CSV data".to_string()) })?;
                let username = &record[2];
                let amount: f64 = record[3].parse().map_err(|e| { error!("Invalid amount: {}", e); (StatusCode::BAD_REQUEST, "Invalid amount".to_string()) })?;
                let interest_rate: f64 = record[4].parse().map_err(|e| { error!("Invalid interest_rate: {}", e); (StatusCode::BAD_REQUEST, "Invalid interest rate".to_string()) })?;
                let status = &record[5];
                let disbursed_at = if record[6].is_empty() {
                    None
                } else {
                    Some(DateTime::parse_from_rfc3339(&record[6])
                        .map(|dt| dt.with_timezone(&Utc))
                        .map_err(|e| { error!("Invalid disbursed_at: {}", e); (StatusCode::BAD_REQUEST, "Invalid disbursed_at format".to_string()) })?)
                };

                let user_id = sqlx::query_scalar!(
                    "SELECT user_id FROM users WHERE username = $1",
                    username
                )
                .fetch_one(&pool)
                .await
                .map_err(|e| { error!("User not found: {}", e); (StatusCode::BAD_REQUEST, "User not found".to_string()) })?;

                sqlx::query!(
                    "INSERT INTO loans (rosca_id, user_id, amount, interest_rate, status, disbursement_status, disbursed_at)
                     VALUES ($1, $2, $3, $4, $5, CASE WHEN $6 = 'completed' THEN 'completed' ELSE 'pending' END, $7)
                     ON CONFLICT (loan_id) DO NOTHING",
                    rosca_id,
                    user_id,
                    amount,
                    interest_rate,
                    status,
                    status,
                    disbursed_at
                )
                .execute(&pool)
                .await
                .map_err(|e| { error!("Database error importing loan: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

                records_imported += 1;
            }
        },
        ("loans", "json") => {
            let records: Vec<serde_json::Value> = serde_json::from_str(&request.data)
                .map_err(|e| { error!("JSON parsing error: {}", e); (StatusCode::BAD_REQUEST, "Invalid JSON data".to_string()) })?;

            for record in records {
                let username = record["username"].as_str()
                    .ok_or_else(|| { error!("Missing username in JSON"); (StatusCode::BAD_REQUEST, "Missing username".to_string()) })?;
                let amount = record["amount"].as_f64()
                    .ok_or_else(|| { error!("Missing or invalid amount in JSON"); (StatusCode::BAD_REQUEST, "Invalid amount".to_string()) })?;
                let interest_rate = record["interest_rate"].as_f64()
                    .ok_or_else(|| { error!("Missing or invalid interest_rate in JSON"); (StatusCode::BAD_REQUEST, "Invalid interest rate".to_string()) })?;
                let status = record["status"].as_str()
                    .ok_or_else(|| { error!("Missing status in JSON"); (StatusCode::BAD_REQUEST, "Missing status".to_string()) })?;
                let disbursed_at = record["disbursed_at"].as_str().map(|s| {
                    DateTime::parse_from_rfc3339(s)
                        .map(|dt| dt.with_timezone(&Utc))
                        .map_err(|e| { error!("Invalid disbursed_at: {}", e); (StatusCode::BAD_REQUEST, "Invalid disbursed_at format".to_string()) })
                }).transpose()?;

                let user_id = sqlx::query_scalar!(
                    "SELECT user_id FROM users WHERE username = $1",
                    username
                )
                .fetch_one(&pool)
                .await
                .map_err(|e| { error!("User not found: {}", e); (StatusCode::BAD_REQUEST, "User not found".to_string()) })?;

                sqlx::query!(
                    "INSERT INTO loans (rosca_id, user_id, amount, interest_rate, status, disbursement_status, disbursed_at)
                     VALUES ($1, $2, $3, $4, $5, CASE WHEN $6 = 'completed' THEN 'completed' ELSE 'pending' END, $7)
                     ON CONFLICT (loan_id) DO NOTHING",
                    rosca_id,
                    user_id,
                    amount,
                    interest_rate,
                    status,
                    status,
                    disbursed_at
                )
                .execute(&pool)
                .await
                .map_err(|e| { error!("Database error importing loan: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

                records_imported += 1;
            }
        },
        ("payouts", "csv") => {
            let mut rdr = csv::Reader::from_reader(request.data.as_bytes());
            let headers = rdr.headers()
                .map_err(|e| { error!("Failed to read CSV headers: {}", e); (StatusCode::BAD_REQUEST, "Invalid CSV format".to_string()) })?
                .clone();
            if !headers.iter().eq(vec!["payout_id", "rosca_name", "username", "amount", "cycle_number", "payout_status", "payout_at"].iter()) {
                error!("Invalid CSV headers: {:?}", headers);
                return Err((StatusCode::BAD_REQUEST, "Invalid CSV headers".to_string()));
            }

            for result in rdr.records() {
                let record = result.map_err(|e| { error!("CSV parsing error: {}", e); (StatusCode::BAD_REQUEST, "Invalid CSV data".to_string()) })?;
                let username = &record[2];
                let amount: f64 = record[3].parse().map_err(|e| { error!("Invalid amount: {}", e); (StatusCode::BAD_REQUEST, "Invalid amount".to_string()) })?;
                let cycle_number: i32 = record[4].parse().map_err(|e| { error!("Invalid cycle_number: {}", e); (StatusCode::BAD_REQUEST, "Invalid cycle number".to_string()) })?;
                let payout_status = &record[5];
                let payout_at = if record[6].is_empty() {
                    None
                } else {
                    Some(DateTime::parse_from_rfc3339(&record[6])
                        .map(|dt| dt.with_timezone(&Utc))
                        .map_err(|e| { error!("Invalid payout_at: {}", e); (StatusCode::BAD_REQUEST, "Invalid payout_at format".to_string()) })?)
                };

                let user_id = sqlx::query_scalar!(
                    "SELECT user_id FROM users WHERE username = $1",
                    username
                )
                .fetch_one(&pool)
                .await
                .map_err(|e| { error!("User not found: {}", e); (StatusCode::BAD_REQUEST, "User not found".to_string()) })?;

                sqlx::query!(
                    "INSERT INTO payouts (rosca_id, user_id, amount, cycle_number, payout_status, payout_at)
                     VALUES ($1, $2, $3, $4, $5, $6)
                     ON CONFLICT (payout_id) DO NOTHING",
                    rosca_id,
                    user_id,
                    amount,
                    cycle_number,
                    payout_status,
                    payout_at
                )
                .execute(&pool)
                .await
                .map_err(|e| { error!("Database error importing payout: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

                records_imported += 1;
            }
        },
        ("payouts", "json") => {
            let records: Vec<serde_json::Value> = serde_json::from_str(&request.data)
                .map_err(|e| { error!("JSON parsing error: {}", e); (StatusCode::BAD_REQUEST, "Invalid JSON data".to_string()) })?;

            for record in records {
                let username = record["username"].as_str()
                    .ok_or_else(|| { error!("Missing username in JSON"); (StatusCode::BAD_REQUEST, "Missing username".to_string()) })?;
                let amount = record["amount"].as_f64()
                    .ok_or_else(|| { error!("Missing or invalid amount in JSON"); (StatusCode::BAD_REQUEST, "Invalid amount".to_string()) })?;
                let cycle_number = record["cycle_number"].as_i64()
                    .ok_or_else(|| { error!("Missing or invalid cycle_number in JSON"); (StatusCode::BAD_REQUEST, "Invalid cycle number".to_string()) })? as i32;
                let payout_status = record["payout_status"].as_str()
                    .ok_or_else(|| { error!("Missing payout_status in JSON"); (StatusCode::BAD_REQUEST, "Missing payout status".to_string()) })?;
                let payout_at = record["payout_at"].as_str().map(|s| {
                    DateTime::parse_from_rfc3339(s)
                        .map(|dt| dt.with_timezone(&Utc))
                        .map_err(|e| { error!("Invalid payout_at: {}", e); (StatusCode::BAD_REQUEST, "Invalid payout_at format".to_string()) })
                }).transpose()?;

                let user_id = sqlx::query_scalar!(
                    "SELECT user_id FROM users WHERE username = $1",
                    username
                )
                .fetch_one(&pool)
                .await
                .map_err(|e| { error!("User not found: {}", e); (StatusCode::BAD_REQUEST, "User not found".to_string()) })?;

                sqlx::query!(
                    "INSERT INTO payouts (rosca_id, user_id, amount, cycle_number, payout_status, payout_at)
                     VALUES ($1, $2, $3, $4, $5, $6)
                     ON CONFLICT (payout_id) DO NOTHING",
                    rosca_id,
                    user_id,
                    amount,
                    cycle_number,
                    payout_status,
                    payout_at
                )
                .execute(&pool)
                .await
                .map_err(|e| { error!("Database error importing payout: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

                records_imported += 1;
            }
        },
        ("members", "csv") => {
            let mut rdr = csv::Reader::from_reader(request.data.as_bytes());
            let headers = rdr.headers()
                .map_err(|e| { error!("Failed to read CSV headers: {}", e); (StatusCode::BAD_REQUEST, "Invalid CSV format".to_string()) })?
                .clone();
            if !headers.iter().eq(vec!["user_id", "rosca_name", "username", "status", "member_type", "joined_at"].iter()) {
                error!("Invalid CSV headers: {:?}", headers);
                return Err((StatusCode::BAD_REQUEST, "Invalid CSV headers".to_string()));
            }

            for result in rdr.records() {
                let record = result.map_err(|e| { error!("CSV parsing error: {}", e); (StatusCode::BAD_REQUEST, "Invalid CSV data".to_string()) })?;
                let user_id: i32 = record[0].parse().map_err(|e| { error!("Invalid user_id: {}", e); (StatusCode::BAD_REQUEST, "Invalid user_id".to_string()) })?;
                let status = &record[3];
                let member_type = &record[4];
                let joined_at = if record[5].is_empty() {
                    None
                } else {
                    Some(DateTime::parse_from_rfc3339(&record[5])
                        .map(|dt| dt.with_timezone(&Utc))
                        .map_err(|e| { error!("Invalid joined_at: {}", e); (StatusCode::BAD_REQUEST, "Invalid joined_at format".to_string()) })?)
                };

                sqlx::query!(
                    "INSERT INTO rosca_members (rosca_id, user_id, status, member_type, joined_at)
                     VALUES ($1, $2, $3, $4, $5)
                     ON CONFLICT (rosca_id, user_id) DO UPDATE
                     SET status = EXCLUDED.status, member_type = EXCLUDED.member_type, joined_at = EXCLUDED.joined_at",
                    rosca_id,
                    user_id,
                    status,
                    member_type,
                    joined_at
                )
                .execute(&pool)
                .await
                .map_err(|e| { error!("Database error importing member: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

                records_imported += 1;
            }
        },
        ("members", "json") => {
            let records: Vec<serde_json::Value> = serde_json::from_str(&request.data)
                .map_err(|e| { error!("JSON parsing error: {}", e); (StatusCode::BAD_REQUEST, "Invalid JSON data".to_string()) })?;

            for record in records {
                let user_id = record["user_id"].as_i64()
                    .ok_or_else(|| { error!("Missing or invalid user_id in JSON"); (StatusCode::BAD_REQUEST, "Invalid user_id".to_string()) })? as i32;
                let status = record["status"].as_str()
                    .ok_or_else(|| { error!("Missing status in JSON"); (StatusCode::BAD_REQUEST, "Missing status".to_string()) })?;
                let member_type = record["member_type"].as_str()
                    .ok_or_else(|| { error!("Missing member_type in JSON"); (StatusCode::BAD_REQUEST, "Missing member type".to_string()) })?;
                let joined_at = record["joined_at"].as_str().map(|s| {
                    DateTime::parse_from_rfc3339(s)
                        .map(|dt| dt.with_timezone(&Utc))
                        .map_err(|e| { error!("Invalid joined_at: {}", e); (StatusCode::BAD_REQUEST, "Invalid joined_at format".to_string()) })
                }).transpose()?;

                sqlx::query!(
                    "INSERT INTO rosca_members (rosca_id, user_id, status, member_type, joined_at)
                     VALUES ($1, $2, $3, $4, $5)
                     ON CONFLICT (rosca_id, user_id) DO UPDATE
                     SET status = EXCLUDED.status, member_type = EXCLUDED.member_type, joined_at = EXCLUDED.joined_at",
                    rosca_id,
                    user_id,
                    status,
                    member_type,
                    joined_at
                )
                .execute(&pool)
                .await
                .map_err(|e| { error!("Database error importing member: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

                records_imported += 1;
            }
        },
        _ => unreachable!(), // Valid combinations already checked
    }

    info!("Imported {} records for rosca_id: {}", records_imported, rosca_id);
    Ok(Json(ImportResponse {
        rosca_id,
        records_imported,
        message: format!("Successfully imported {} records", records_imported),
    }))
}

// Endpoint 68: GET /api/v1/roscas/:rosca_id/analytics - Get ROSCA analytics
#[derive(Deserialize)]
struct AnalyticsFilter {
    metric: Option<String>,
    start_time: Option<DateTime<Utc>>,
    end_time: Option<DateTime<Utc>>,
    granularity: Option<String>,
}

#[derive(Serialize)]
struct ContributionTrendData {
    period: String,
    total_amount: f64,
    contribution_count: i64,
    avg_amount: f64,
}

#[derive(Serialize)]
struct LoanRepaymentData {
    total_loans: i64,
    total_disbursed: f64,
    total_repaid: f64,
    repayment_rate: f64,
    overdue_loans: i64,
    overdue_amount: f64,
}

#[derive(Serialize)]
struct MemberActivityData {
    active_members: i64,
    inactive_members: i64,
    total_contributions: i64,
    total_loans: i64,
    total_payouts: i64,
    participation_rate: f64,
}

#[derive(Serialize)]
#[serde(tag = "metric")]
enum AnalyticsResponse {
    #[serde(rename = "contribution_trends")]
    ContributionTrends { rosca_id: i32, start_time: Option<DateTime<Utc>>, end_time: Option<DateTime<Utc>>, granularity: String, data: Vec<ContributionTrendData> },
    #[serde(rename = "loan_repayment")]
    LoanRepayment { rosca_id: i32, start_time: Option<DateTime<Utc>>, end_time: Option<DateTime<Utc>>, data: LoanRepaymentData },
    #[serde(rename = "member_activity")]
    MemberActivity { rosca_id: i32, start_time: Option<DateTime<Utc>>, end_time: Option<DateTime<Utc>>, data: MemberActivityData },
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
pub async fn get_rosca_analytics(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path(rosca_id): Path<i32>,
    Query(filter): Query<AnalyticsFilter>,
) -> Result<Json<AnalyticsResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Generating analytics for rosca_id: {} by user_id: {}", rosca_id, auth_user.user_id);
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

    // Determine the analytics metric and granularity
    let metric = filter.metric.unwrap_or_else(|| "contribution_trends".to_string());
    let start_time = filter.start_time.unwrap_or_else(|| Utc::now() - Duration::days(365)); // Default to last year
    let end_time = filter.end_time.unwrap_or_else(Utc::now);
    let granularity = filter.granularity.unwrap_or_else(|| "monthly".to_string());

    debug!("Generating {} analytics for rosca_id: {} with granularity: {}", metric, rosca_id, granularity);

    match metric.as_str() {
        "contribution_trends" => {
            let valid_granularities = vec!["daily", "weekly", "monthly", "yearly"];
            if !valid_granularities.contains(&granularity.as_str()) {
                error!("Invalid granularity: {}", granularity);
                return Err((StatusCode::BAD_REQUEST, "Invalid granularity".to_string()));
            }

            let interval = match granularity.as_str() {
                "daily" => "1 day",
                "weekly" => "1 week",
                "monthly" => "1 month",
                "yearly" => "1 year",
                _ => unreachable!(),
            };

            let query = format!(
                r#"
                SELECT 
                    date_trunc($2, paid_at) AS period,
                    COALESCE(SUM(amount), 0.0) AS total_amount,
                    COUNT(*) AS contribution_count,
                    COALESCE(AVG(amount), 0.0) AS avg_amount
                FROM contributions
                WHERE rosca_id = $1 AND status = 'completed' AND paid_at BETWEEN $3 AND $4
                GROUP BY date_trunc($2, paid_at)
                ORDER BY period
                "#
            );
            let trends = sqlx::query_as::<_, ContributionTrendData>(&query)
                .bind(rosca_id)
                .bind(&granularity)
                .bind(start_time)
                .bind(end_time)
                .fetch_all(&pool)
                .await
                .map_err(|e| { error!("Database error fetching contribution trends: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

            info!("Contribution trends generated for rosca_id: {} with {} records", rosca_id, trends.len());
            Ok(Json(AnalyticsResponse::ContributionTrends {
                rosca_id,
                start_time: Some(start_time),
                end_time: Some(end_time),
                granularity,
                data: trends,
            }))
        },
        "loan_repayment" => {
            let repayment_data = sqlx::query!(
                r#"
                SELECT 
                    COUNT(*) AS total_loans,
                    COALESCE(SUM(l.amount), 0.0) AS total_disbursed,
                    COALESCE(SUM(COALESCE((SELECT SUM(lr.amount + lr.interest_amount) FROM loan_repayments lr WHERE lr.loan_id = l.loan_id), 0)), 0.0) AS total_repaid,
                    COUNT(CASE WHEN l.status = 'active' AND NOW() > l.disbursed_at + INTERVAL '30 days' THEN 1 END) AS overdue_loans,
                    COALESCE(SUM(CASE WHEN l.status = 'active' AND NOW() > l.disbursed_at + INTERVAL '30 days' THEN l.amount ELSE 0 END), 0.0) AS overdue_amount
                FROM loans l
                WHERE l.rosca_id = $1 AND l.disbursement_status = 'completed' AND l.created_at BETWEEN $2 AND $3
                "#,
                rosca_id,
                start_time,
                end_time
            )
            .fetch_one(&pool)
            .await
            .map_err(|e| { error!("Database error fetching loan repayment data: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

            let total_repaid = repayment_data.total_repaid.unwrap_or(0.0);
            let total_disbursed = repayment_data.total_disbursed.unwrap_or(0.0);
            let repayment_rate = if total_disbursed > 0.0 { total_repaid / total_disbursed } else { 0.0 };

            info!("Loan repayment analytics generated for rosca_id: {}", rosca_id);
            Ok(Json(AnalyticsResponse::LoanRepayment {
                rosca_id,
                start_time: Some(start_time),
                end_time: Some(end_time),
                data: LoanRepaymentData {
                    total_loans: repayment_data.total_loans,
                    total_disbursed,
                    total_repaid,
                    repayment_rate,
                    overdue_loans: repayment_data.overdue_loans.unwrap_or(0),
                    overdue_amount: repayment_data.overdue_amount.unwrap_or(0.0),
                },
            }))
        },
        "member_activity" => {
            let activity = sqlx::query!(
                r#"
                WITH contrib AS (
                    SELECT COUNT(*) AS total_contribs, COUNT(DISTINCT user_id) AS active_users
                    FROM contributions
                    WHERE rosca_id = $1 AND status = 'completed' AND paid_at BETWEEN $2 AND $3
                ),
                loans AS (
                    SELECT COUNT(*) AS total_loans
                    FROM loans
                    WHERE rosca_id = $1 AND disbursement_status = 'completed' AND created_at BETWEEN $2 AND $3
                ),
                payouts AS (
                    SELECT COUNT(*) AS total_payouts
                    FROM payouts
                    WHERE rosca_id = $1 AND payout_at BETWEEN $2 AND $3
                )
                SELECT 
                    (SELECT COUNT(*) FROM rosca_members WHERE rosca_id = $1 AND status = 'active') AS active_members,
                    (SELECT COUNT(*) FROM rosca_members WHERE rosca_id = $1 AND status != 'active') AS inactive_members,
                    COALESCE(c.total_contribs, 0) AS total_contributions,
                    COALESCE(l.total_loans, 0) AS total_loans,
                    COALESCE(p.total_payouts, 0) AS total_payouts,
                    COALESCE(CAST(c.active_users AS FLOAT) / NULLIF((SELECT COUNT(*) FROM rosca_members WHERE rosca_id = $1 AND status = 'active'), 0), 0.0) AS participation_rate
                FROM contrib c, loans l, payouts p
                "#,
                rosca_id,
                start_time,
                end_time
            )
            .fetch_one(&pool)
            .await
            .map_err(|e| { error!("Database error fetching member activity: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

            info!("Member activity analytics generated for rosca_id: {}", rosca_id);
            Ok(Json(AnalyticsResponse::MemberActivity {
                rosca_id,
                start_time: Some(start_time),
                end_time: Some(end_time),
                data: MemberActivityData {
                    active_members: activity.active_members.unwrap_or(0),
                    inactive_members: activity.inactive_members.unwrap_or(0),
                    total_contributions: activity.total_contributions.unwrap_or(0),
                    total_loans: activity.total_loans.unwrap_or(0),
                    total_payouts: activity.total_payouts.unwrap_or(0),
                    participation_rate: activity.participation_rate.unwrap_or(0.0),
                },
            }))
        },
        _ => {
            error!("Invalid metric: {}", metric);
            Err((StatusCode::BAD_REQUEST, "Invalid metric".to_string()))
        },
    }
}

// Endpoint 70: GET /api/v1/roscas/:rosca_id/forecast - Forecast ROSCA financials
#[derive(Deserialize)]
struct ForecastFilter {
    metric: Option<String>,
    horizon: Option<i32>,
    start_date: Option<DateTime<Utc>>,
    granularity: Option<String>,
}

#[derive(Serialize)]
struct ContributionForecastData {
    period: String,
    predicted_amount: f64,
    confidence_interval: [f64; 2],
}

#[derive(Serialize)]
struct LoanRepaymentForecastData {
    period: String,
    projected_repayment: f64,
    confidence_interval: [f64; 2],
}

#[derive(Serialize)]
struct PayoutScheduleData {
    period: String,
    projected_payout: f64,
    eligible_members: i64,
}

#[derive(Serialize)]
#[serde(tag = "metric")]
enum ForecastResponse {
    #[serde(rename = "contribution_forecast")]
    ContributionForecast { rosca_id: i32, horizon: i32, start_date: DateTime<Utc>, granularity: String, data: Vec<ContributionForecastData> },
    #[serde(rename = "loan_repayment_forecast")]
    LoanRepaymentForecast { rosca_id: i32, horizon: i32, start_date: DateTime<Utc>, granularity: String, total_projected_repayment: f64, data: Vec<LoanRepaymentForecastData> },
    #[serde(rename = "payout_schedule")]
    PayoutSchedule { rosca_id: i32, horizon: i32, start_date: DateTime<Utc>, granularity: String, data: Vec<PayoutScheduleData> },
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
pub async fn get_rosca_forecast(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path(rosca_id): Path<i32>,
    Query(filter): Query<ForecastFilter>,
) -> Result<Json<ForecastResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Generating forecast for rosca_id: {} by user_id: {}", rosca_id, auth_user.user_id);
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

    // Determine forecast parameters
    let metric = filter.metric.unwrap_or_else(|| "contribution_forecast".to_string());
    let horizon = filter.horizon.unwrap_or(6).max(1); // Default to 6 periods, min 1
    let start_date = filter.start_date.unwrap_or_else(Utc::now);
    let granularity = filter.granularity.unwrap_or_else(|| "monthly".to_string());

    debug!("Generating {} forecast for rosca_id: {} with horizon: {} and granularity: {}", metric, rosca_id, horizon, granularity);

    let valid_granularities = vec!["daily", "weekly", "monthly", "yearly"];
    if !valid_granularities.contains(&granularity.as_str()) {
        error!("Invalid granularity: {}", granularity);
        return Err((StatusCode::BAD_REQUEST, "Invalid granularity".to_string()));
    }

    let period_duration = match granularity.as_str() {
        "daily" => Duration::days(1),
        "weekly" => Duration::days(7),
        "monthly" => Duration::days(30), // Simplified approximation
        "yearly" => Duration::days(365),
        _ => unreachable!(),
    };

    match metric.as_str() {
        "contribution_forecast" => {
            // Fetch historical contribution averages (last 12 months as baseline)
            let avg_contribution = sqlx::query_scalar!(
                "SELECT COALESCE(AVG(amount), 0.0) 
                 FROM contributions 
                 WHERE rosca_id = $1 AND status = 'completed' AND paid_at >= $2",
                rosca_id,
                Utc::now() - Duration::days(365)
            )
            .fetch_one(&pool)
            .await
            .map_err(|e| { error!("Database error fetching contribution average: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
            .unwrap_or(0.0);

            // Simple linear forecast with ±10% confidence interval
            let mut data = Vec::new();
            let mut current_date = start_date;
            for i in 0..horizon {
                let period = match granularity.as_str() {
                    "daily" => current_date.format("%Y-%m-%d").to_string(),
                    "weekly" => current_date.format("%Y-W%W").to_string(),
                    "monthly" => current_date.format("%Y-%m").to_string(),
                    "yearly" => current_date.format("%Y").to_string(),
                    _ => unreachable!(),
                };
                let predicted_amount = avg_contribution * (1.0 + i as f64 * 0.01); // 1% growth per period
                data.push(ContributionForecastData {
                    period,
                    predicted_amount,
                    confidence_interval: [predicted_amount * 0.9, predicted_amount * 1.1], // ±10%
                });
                current_date = current_date + period_duration;
            }

            info!("Contribution forecast generated for rosca_id: {} with {} periods", rosca_id, data.len());
            Ok(Json(ForecastResponse::ContributionForecast {
                rosca_id,
                horizon,
                start_date,
                granularity,
                data,
            }))
        },
        "loan_repayment_forecast" => {
            // Fetch historical repayment data (last 12 months)
            let repayment_stats = sqlx::query!(
                "SELECT 
                    COALESCE(SUM(l.amount), 0.0) AS total_disbursed,
                    COALESCE(SUM(COALESCE((SELECT SUM(lr.amount + lr.interest_amount) FROM loan_repayments lr WHERE lr.loan_id = l.loan_id), 0)), 0.0) AS total_repaid
                 FROM loans l
                 WHERE l.rosca_id = $1 AND l.disbursement_status = 'completed' AND l.created_at >= $2",
                rosca_id,
                Utc::now() - Duration::days(365)
            )
            .fetch_one(&pool)
            .await
            .map_err(|e| { error!("Database error fetching repayment stats: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

            let total_disbursed = repayment_stats.total_disbursed.unwrap_or(0.0);
            let total_repaid = repayment_stats.total_repaid.unwrap_or(0.0);
            let repayment_rate = if total_disbursed > 0.0 { total_repaid / total_disbursed } else { 0.0 };
            let avg_monthly_repayment = if total_disbursed > 0.0 { total_repaid / 12.0 } else { 0.0 };

            // Simple forecast based on historical repayment rate
            let mut data = Vec::new();
            let mut current_date = start_date;
            let mut cumulative_repayment = total_repaid;
            for i in 0..horizon {
                let period = match granularity.as_str() {
                    "daily" => current_date.format("%Y-%m-%d").to_string(),
                    "weekly" => current_date.format("%Y-W%W").to_string(),
                    "monthly" => current_date.format("%Y-%m").to_string(),
                    "yearly" => current_date.format("%Y").to_string(),
                    _ => unreachable!(),
                };
                let projected_repayment = avg_monthly_repayment * (1.0 + i as f64 * 0.005); // 0.5% growth per period
                cumulative_repayment += projected_repayment;
                data.push(LoanRepaymentForecastData {
                    period,
                    projected_repayment,
                    confidence_interval: [projected_repayment * 0.9, projected_repayment * 1.1], // ±10%
                });
                current_date = current_date + period_duration;
            }

            info!("Loan repayment forecast generated for rosca_id: {} with {} periods", rosca_id, data.len());
            Ok(Json(ForecastResponse::LoanRepaymentForecast {
                rosca_id,
                horizon,
                start_date,
                granularity,
                total_projected_repayment: cumulative_repayment,
                data,
            }))
        },
        "payout_schedule" => {
            // Fetch payout cycle and contribution amount from roscas table
            let rosca_info = sqlx::query!(
                "SELECT payout_cycle, contribution_amount 
                 FROM roscas 
                 WHERE rosca_id = $1",
                rosca_id
            )
            .fetch_one(&pool)
            .await
            .map_err(|e| { error!("Database error fetching ROSCA info: {}", e); (StatusCode::NOT_FOUND, "ROSCA not found".to_string()) })?;

            let payout_cycle = rosca_info.payout_cycle;
            let contribution_amount = rosca_info.contribution_amount;

            // Estimate eligible members (simplified: active members with enough contributions)
            let eligible_members = sqlx::query_scalar!(
                "SELECT COUNT(*) 
                 FROM rosca_members rm 
                 WHERE rm.rosca_id = $1 AND rm.status = 'active' 
                 AND (SELECT COUNT(*) FROM contributions c WHERE c.rosca_id = $1 AND c.user_id = rm.user_id AND c.status = 'completed') >= 1",
                rosca_id
            )
            .fetch_one(&pool)
            .await
            .map_err(|e| { error!("Database error counting eligible members: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
            .unwrap_or(0);

            // Simplified forecast: assume payouts occur every payout_cycle periods
            let mut data = Vec::new();
            let mut current_date = start_date;
            let cycle_duration = period_duration * payout_cycle as i32;
            for i in 0..horizon {
                let period = match granularity.as_str() {
                    "daily" => current_date.format("%Y-%m-%d").to_string(),
                    "weekly" => current_date.format("%Y-W%W").to_string(),
                    "monthly" => current_date.format("%Y-%m").to_string(),
                    "yearly" => current_date.format("%Y").to_string(),
                    _ => unreachable!(),
                };
                let projected_payout = if i % payout_cycle == 0 && eligible_members > 0 {
                    contribution_amount * eligible_members as f64 // Assume full payout per cycle
                } else {
                    0.0
                };
                data.push(PayoutScheduleData {
                    period,
                    projected_payout,
                    eligible_members,
                });
                current_date = current_date + period_duration;
            }

            info!("Payout schedule forecast generated for rosca_id: {} with {} periods", rosca_id, data.len());
            Ok(Json(ForecastResponse::PayoutSchedule {
                rosca_id,
                horizon,
                start_date,
                granularity,
                data,
            }))
        },
        _ => {
            error!("Invalid metric: {}", metric);
            Err((StatusCode::BAD_REQUEST, "Invalid metric".to_string()))
        },
    }
}

// Endpoint 72: GET /api/v1/roscas/:rosca_id/notifications - List ROSCA notifications
#[derive(Deserialize)]
struct NotificationFilter {
    #[serde(rename = "type")]
    notification_type: Option<String>,
    status: Option<String>,
    start_time: Option<DateTime<Utc>>,
    end_time: Option<DateTime<Utc>>,
    limit: Option<i32>,
    offset: Option<i32>,
}

#[derive(Serialize, sqlx::FromRow)]
struct Notification {
    notification_id: i32,
    rosca_id: i32,
    user_id: Option<i32>,
    notification_type: String,
    message: String,
    status: String,
    created_at: DateTime<Utc>,
    sent_at: Option<DateTime<Utc>>,
    read_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
struct NotificationResponse {
    rosca_id: i32,
    notifications: Vec<Notification>,
    total_count: i64,
    limit: i32,
    offset: i32,
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
pub async fn get_rosca_notifications(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path(rosca_id): Path<i32>,
    Query(filter): Query<NotificationFilter>,
) -> Result<Json<NotificationResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Retrieving notifications for rosca_id: {} by user_id: {}", rosca_id, auth_user.user_id);
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

    // Apply filters for notifications
    let limit = filter.limit.unwrap_or(50).max(1).min(100);
    let offset = filter.offset.unwrap_or(0).max(0);
    let mut conditions = vec!["n.rosca_id = $1"];
    let mut params: Vec<&(dyn sqlx::Encode<'_, sqlx::Postgres> + sqlx::Type<sqlx::Postgres> + Sync)> = vec![&rosca_id];
    let mut param_index = 2;

    if let Some(ref notification_type) = filter.notification_type {
        conditions.push(format!("n.notification_type = ${}", param_index));
        params.push(notification_type);
        param_index += 1;
    }
    if let Some(ref status) = filter.status {
        conditions.push(format!("n.status = ${}", param_index));
        params.push(status);
        param_index += 1;
    }
    if let Some(start_time) = filter.start_time {
        conditions.push(format!("n.created_at >= ${}", param_index));
        params.push(&start_time);
        param_index += 1;
    }
    if let Some(end_time) = filter.end_time {
        conditions.push(format!("n.created_at <= ${}", param_index));
        params.push(&end_time);
        param_index += 1;
    }

    // Fetch total count for pagination
    let total_count_query = format!(
        "SELECT COUNT(*) FROM rosca_notifications n WHERE {}",
        if conditions.is_empty() { "n.rosca_id = $1" } else { conditions.join(" AND ") }
    );
    let total_count = sqlx::query_scalar_with(&total_count_query, params.clone())
        .fetch_one(&pool)
        .await
        .map_err(|e| { error!("Database error fetching total count: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
        .unwrap_or(0);

    // Fetch notifications with pagination
    let query = format!(
        r#"
        SELECT 
            n.notification_id,
            n.rosca_id,
            n.user_id,
            n.notification_type,
            n.message,
            n.status,
            n.created_at,
            n.sent_at,
            n.read_at
        FROM rosca_notifications n
        {}
        ORDER BY n.created_at DESC
        LIMIT ${} OFFSET ${}
        "#,
        if conditions.is_empty() { "WHERE n.rosca_id = $1" } else { format!("WHERE {}", conditions.join(" AND ")) },
        param_index,
        param_index + 1
    );
    params.push(&limit);
    params.push(&offset);

    let notifications = sqlx::query_as_with::<_, Notification, _>(&query, params)
        .fetch_all(&pool)
        .await
        .map_err(|e| { error!("Database error fetching notifications: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    info!("Retrieved {} notifications for rosca_id: {}", notifications.len(), rosca_id);
    Ok(Json(NotificationResponse {
        rosca_id,
        notifications,
        total_count,
        limit,
        offset,
    }))
}

// Endpoint 74: GET /api/v1/roscas - List all ROSCAs
#[derive(Deserialize)]
struct RoscaFilter {
    status: Option<String>,
    min_members: Option<i32>,
    limit: Option<i32>,
    offset: Option<i32>,
}

#[derive(Serialize, sqlx::FromRow)]
struct RoscaSummary {
    rosca_id: i32,
    name: String,
    contribution_amount: f64,
    cycle_type: String,
    payout_cycle: i32,
    interest_rate: f64,
    status: String,
    member_count: i64,
    created_at: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id))]
pub async fn list_roscas(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Query(filter): Query<RoscaFilter>,
) -> Result<Json<Vec<RoscaSummary>>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Listing ROSCAs by user_id: {}", auth_user.user_id);
    tracing::Span::current().record("user_id", &auth_user.user_id);

    // Check if user has platform-wide read permission
    let has_permission = sqlx::query_scalar!(
        r#"
        SELECT 1
        FROM permissions p
        JOIN users u ON u.role_id = p.role_id
        WHERE u.user_id = $1 AND p.api_endpoint = '/api/v1/roscas' AND p.permission_type = 'read'
        "#,
        auth_user.user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking permissions: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if !has_permission {
        error!("User {} lacks read permission for /api/v1/roscas", auth_user.user_id);
        return Err((StatusCode::FORBIDDEN, "User lacks read permission".to_string()));
    }

    // Apply filters for ROSCA listing
    let limit = filter.limit.unwrap_or(50).max(1).min(100);
    let offset = filter.offset.unwrap_or(0).max(0);
    let mut conditions = Vec::new();
    let mut params: Vec<&(dyn sqlx::Encode<'_, sqlx::Postgres> + sqlx::Type<sqlx::Postgres> + Sync)> = Vec::new();
    let mut param_index = 1;

    if let Some(ref status) = filter.status {
        conditions.push(format!("r.status = ${}", param_index));
        params.push(status);
        param_index += 1;
    }
    if let Some(min_members) = filter.min_members {
        conditions.push(format!("(SELECT COUNT(*) FROM rosca_members rm WHERE rm.rosca_id = r.rosca_id) >= ${}", param_index));
        params.push(&min_members);
        param_index += 1;
    }

    // Build and execute the query
    let where_clause = if conditions.is_empty() { String::new() } else { format!("WHERE {}", conditions.join(" AND ")) };
    let query = format!(
        r#"
        SELECT 
            r.rosca_id,
            r.name,
            r.contribution_amount,
            r.cycle_type,
            r.payout_cycle,
            r.interest_rate,
            r.status,
            (SELECT COUNT(*) FROM rosca_members rm WHERE rm.rosca_id = r.rosca_id) AS member_count,
            r.created_at
        FROM roscas r
        {} 
        ORDER BY r.created_at DESC
        LIMIT ${} OFFSET ${}
        "#,
        where_clause,
        param_index,
        param_index + 1
    );
    params.push(&limit);
    params.push(&offset);

    let roscas = sqlx::query_as_with::<_, RoscaSummary, _>(&query, params)
        .fetch_all(&pool)
        .await
        .map_err(|e| { error!("Database error fetching ROSCAs: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    info!("Retrieved {} ROSCAs for user_id: {}", roscas.len(), auth_user.user_id);
    Ok(Json(roscas))
}

// Endpoint 75: GET /api/v1/roscas/:rosca_id - Get ROSCA details
#[derive(Serialize, sqlx::FromRow)]
struct RoscaDetail {
    rosca_id: i32,
    name: String,
    contribution_amount: f64,
    cycle_type: String,
    payout_cycle: i32,
    interest_rate: f64,
    status: String,
    member_count: i64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
pub async fn get_rosca(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path(rosca_id): Path<i32>,
) -> Result<Json<RoscaDetail>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Retrieving ROSCA details for rosca_id: {} by user_id: {}", rosca_id, auth_user.user_id);
    tracing::Span::current()
        .record("user_id", &auth_user.user_id)
        .record("rosca_id", &rosca_id);

    // Check if user is a member of the ROSCA (any member can view details)
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

    // Fetch ROSCA details
    let rosca = sqlx::query_as!(
        RoscaDetail,
        r#"
        SELECT 
            r.rosca_id,
            r.name,
            r.contribution_amount,
            r.cycle_type,
            r.payout_cycle,
            r.interest_rate,
            r.status,
            (SELECT COUNT(*) FROM rosca_members rm WHERE rm.rosca_id = r.rosca_id) AS member_count,
            r.created_at,
            r.updated_at
        FROM roscas r
        WHERE r.rosca_id = $1
        "#,
        rosca_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error fetching ROSCA: {}", e); (StatusCode::NOT_FOUND, "ROSCA not found".to_string()) })?;

    info!("ROSCA details retrieved: rosca_id={}", rosca.rosca_id);
    Ok(Json(rosca))
}

// Endpoint 78: GET /api/v1/roscas/:rosca_id/audit - Retrieve audit logs
#[derive(Deserialize)]
struct AuditFilter {
    action: Option<String>,
    start_time: Option<DateTime<Utc>>,
    end_time: Option<DateTime<Utc>>,
    limit: Option<i32>,
    offset: Option<i32>,
}

#[derive(Serialize, sqlx::FromRow)]
struct AuditLog {
    log_id: i32,
    rosca_id: i32,
    user_id: i32,
    username: String,
    action: String,
    details: Option<String>,
    timestamp: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
pub async fn get_rosca_audit(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path(rosca_id): Path<i32>,
    Query(filter): Query<AuditFilter>,
) -> Result<Json<Vec<AuditLog>>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Retrieving audit logs for rosca_id: {} by user_id: {}", rosca_id, auth_user.user_id);
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

    // Apply filters for audit logs
    let limit = filter.limit.unwrap_or(50).max(1).min(100);
    let offset = filter.offset.unwrap_or(0).max(0);
    let mut conditions = vec!["al.rosca_id = $1"];
    let mut params: Vec<&(dyn sqlx::Encode<'_, sqlx::Postgres> + sqlx::Type<sqlx::Postgres> + Sync)> = vec![&rosca_id];
    let mut param_index = 2;

    if let Some(ref action) = filter.action {
        conditions.push(format!("al.action = ${}", param_index));
        params.push(action);
        param_index += 1;
    }
    if let Some(start_time) = filter.start_time {
        conditions.push(format!("al.timestamp >= ${}", param_index));
        params.push(&start_time);
        param_index += 1;
    }
    if let Some(end_time) = filter.end_time {
        conditions.push(format!("al.timestamp <= ${}", param_index));
        params.push(&end_time);
        param_index += 1;
    }

    // Fetch audit logs with pagination
    let query = format!(
        r#"
        SELECT 
            al.log_id,
            al.rosca_id,
            al.user_id,
            u.username,
            al.action,
            al.details,
            al.timestamp
        FROM audit_logs al
        JOIN users u ON al.user_id = u.user_id
        {}
        ORDER BY al.timestamp DESC
        LIMIT ${} OFFSET ${}
        "#,
        if conditions.is_empty() { "WHERE al.rosca_id = $1" } else { format!("WHERE {}", conditions.join(" AND ")) },
        param_index,
        param_index + 1
    );
    params.push(&limit);
    params.push(&offset);

    let logs = sqlx::query_as_with::<_, AuditLog, _>(&query, params)
        .fetch_all(&pool)
        .await
        .map_err(|e| { error!("Database error fetching audit logs: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    info!("Retrieved {} audit logs for rosca_id: {}", logs.len(), rosca_id);
    Ok(Json(logs))
}

// Endpoint 87: GET /api/v1/roscas/:rosca_id/simulation - Simulate ROSCA scenarios
#[derive(Deserialize)]
struct SimulationFilter {
    horizon: Option<i32>,
    contribution_increase: Option<f64>,         // Existing: % increase per period
    loan_increase: Option<f64>,                 // Existing: % increase per period
    member_increase_or_decrease: Option<f64>,   // New: Absolute member count change per period
    cycle_length_increase_or_decrease: Option<f64>, // New: Days change per period
    payout_cycle_increase_or_decrease: Option<f64>, // New: Payout cycle period change
    granularity: Option<String>,
}

#[derive(Serialize)]
struct SimulationResult {
    period: String,
    projected_contributions: f64,
    projected_loans: f64,
    projected_payouts: f64,
}

#[derive(Serialize)]
struct RoscaSimulationResponse {
    rosca_id: i32,
    horizon: i32,
    granularity: String,
    data: Vec<SimulationResult>,
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
pub async fn get_rosca_simulation(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path(rosca_id): Path<i32>,
    Query(filter): Query<SimulationFilter>,
) -> Result<Json<RoscaSimulationResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Simulating ROSCA for rosca_id: {} by user_id: {}", rosca_id, auth_user.user_id);
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

    // Determine simulation parameters
    let horizon = filter.horizon.unwrap_or(6).max(1); // Default to 6 periods, min 1
    let contribution_increase = filter.contribution_increase.unwrap_or(0.0) / 100.0; // % as decimal
    let loan_increase = filter.loan_increase.unwrap_or(0.0) / 100.0; // % as decimal
    let member_increase_or_decrease = filter.member_increase_or_decrease.unwrap_or(0.0); // Absolute change
    let cycle_length_increase_or_decrease = filter.cycle_length_increase_or_decrease.unwrap_or(0.0); // Days change
    let payout_cycle_increase_or_decrease = filter.payout_cycle_increase_or_decrease.unwrap_or(0.0); // Periods change
    let granularity = filter.granularity.unwrap_or_else(|| "monthly".to_string());

    debug!("Simulating with horizon: {}, contribution_increase: {:.2}%, loan_increase: {:.2}%, member_change: {:.2}, cycle_length_change: {:.2}, payout_cycle_change: {:.2}, granularity: {}", 
           horizon, contribution_increase * 100.0, loan_increase * 100.0, member_increase_or_decrease, cycle_length_increase_or_decrease, payout_cycle_increase_or_decrease, granularity);

    let valid_granularities = vec!["daily", "weekly", "monthly", "yearly"];
    if !valid_granularities.contains(&granularity.as_str()) {
        error!("Invalid granularity: {}", granularity);
        return Err((StatusCode::BAD_REQUEST, "Invalid granularity".to_string()));
    }

    let period_duration = match granularity.as_str() {
        "daily" => Duration::days(1),
        "weekly" => Duration::days(7),
        "monthly" => Duration::days(30), // Simplified approximation
        "yearly" => Duration::days(365),
        _ => unreachable!(),
    };

    // Fetch historical averages and ROSCA details (last 12 months)
    let contrib_avg = sqlx::query_scalar!(
        "SELECT COALESCE(AVG(amount), 0.0) 
         FROM contributions 
         WHERE rosca_id = $1 AND status = 'completed' AND paid_at >= $2",
        rosca_id,
        Utc::now() - Duration::days(365)
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error fetching contribution average: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .unwrap_or(0.0);

    let loan_avg = sqlx::query_scalar!(
        "SELECT COALESCE(AVG(amount), 0.0) 
         FROM loans 
         WHERE rosca_id = $1 AND disbursement_status = 'completed' AND created_at >= $2",
        rosca_id,
        Utc::now() - Duration::days(365)
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error fetching loan average: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .unwrap_or(0.0);

    let payout_avg = sqlx::query_scalar!(
        "SELECT COALESCE(AVG(amount), 0.0) 
         FROM payouts 
         WHERE rosca_id = $1 AND payout_at >= $2",
        rosca_id,
        Utc::now() - Duration::days(365)
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error fetching payout average: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .unwrap_or(0.0);

    let rosca_info = sqlx::query!(
        "SELECT contribution_amount, payout_cycle 
         FROM roscas 
         WHERE rosca_id = $1",
        rosca_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error fetching ROSCA info: {}", e); (StatusCode::NOT_FOUND, "ROSCA not found".to_string()) })?;

    let member_count = sqlx::query_scalar!(
        "SELECT COUNT(*) 
         FROM rosca_members 
         WHERE rosca_id = $1 AND status = 'active'",
        rosca_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error fetching member count: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .unwrap_or(0) as f64;

    // Simulation parameters
    let base_contribution_amount = rosca_info.contribution_amount;
    let base_payout_cycle = rosca_info.payout_cycle as f64;

    // Generate simulation data
    let mut data = Vec::new();
    let mut current_date = Utc::now();
    for i in 0..horizon {
        let period = match granularity.as_str() {
            "daily" => current_date.format("%Y-%m-%d").to_string(),
            "weekly" => current_date.format("%Y-W%W").to_string(),
            "monthly" => current_date.format("%Y-%m").to_string(),
            "yearly" => current_date.format("%Y").to_string(),
            _ => unreachable!(),
        };

        let i_f64 = i as f64;
        let contrib_factor = 1.0 + (i_f64 * contribution_increase);
        let loan_factor = 1.0 + (i_f64 * loan_increase);
        let member_factor = member_count + (i_f64 * member_increase_or_decrease); // Absolute change
        let cycle_length_factor = period_duration.num_days() as f64 + (i_f64 * cycle_length_increase_or_decrease); // Adjusted cycle length in days
        let payout_cycle_factor = base_payout_cycle + (i_f64 * payout_cycle_increase_or_decrease); // Adjusted payout cycle

        // Projected contributions: avg * contribution increase * member count adjustment
        let projected_contributions = contrib_avg * contrib_factor * member_factor.max(0.0); // Ensure non-negative

        // Projected loans: avg * loan increase * member count adjustment
        let projected_loans = loan_avg * loan_factor * member_factor.max(0.0); // Ensure non-negative

        // Projected payouts: avg * member count adjustment, adjusted by payout cycle frequency
        let payout_frequency = if payout_cycle_factor > 0.0 { 1.0 / payout_cycle_factor } else { 1.0 }; // Simplified frequency
        let projected_payouts = payout_avg * member_factor.max(0.0) * payout_frequency;

        data.push(SimulationResult {
            period,
            projected_contributions,
            projected_loans,
            projected_payouts,
        });

        current_date = current_date + Duration::days(cycle_length_factor.round() as i64); // Adjust cycle length per period
    }

    info!("Simulation completed for rosca_id: {} with {} periods", rosca_id, data.len());
    Ok(Json(RoscaSimulationResponse {
        rosca_id,
        horizon,
        granularity,
        data,
    }))
}
