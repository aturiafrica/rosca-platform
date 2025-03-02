// src/handlers/user.rs
// User endpoint handlers for the ROSCA Platform API

use axum::{http::{StatusCode, HeaderValue}, extract::{State, Path, Query}, Json};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{debug, error, info, instrument};
use chrono::{DateTime, Utc};
use crate::handlers::auth::extract_auth_user;

// Authentication extractor
struct AuthUser { user_id: i32; }

// Endpoint: GET /api/v1/users - List all users (admin-only)
#[derive(Deserialize)]
struct UserFilter {
    limit: Option<i32>,
    offset: Option<i32>,
}

#[derive(Serialize, sqlx::FromRow)]
struct User {
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
pub async fn list_users(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Query(filter): Query<UserFilter>,
) -> Result<Json<Vec<User>>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Listing all users by user_id: {}", auth_user.user_id);
    tracing::Span::current().record("user_id", &auth_user.user_id);

    // Check if user has platform-wide read permission
    let has_permission = sqlx::query_scalar!(
        r#"
        SELECT 1
        FROM permissions p
        JOIN users u ON u.role_id = p.role_id
        WHERE u.user_id = $1 AND p.api_endpoint = '/api/v1/users' AND p.permission_type = 'read'
        "#,
        auth_user.user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking permissions: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if !has_permission {
        error!("User {} lacks read permission for /api/v1/users", auth_user.user_id);
        return Err((StatusCode::FORBIDDEN, "User lacks read permission".to_string()));
    }

    // Apply filters for users
    let limit = filter.limit.unwrap_or(50).max(1).min(100);
    let offset = filter.offset.unwrap_or(0).max(0);

    // Fetch all users with pagination
    let users = sqlx::query_as!(
        User,
        r#"
        SELECT 
            user_id,
            username,
            email,
            phone,
            first_name,
            last_name,
            created_at,
            updated_at
        FROM users
        ORDER BY created_at DESC
        LIMIT $1 OFFSET $2
        "#,
        limit as i64,
        offset as i64
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| { error!("Database error fetching users: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    info!("Retrieved {} users for user_id: {}", users.len(), auth_user.user_id);
    Ok(Json(users))
}

// Endpoint: PATCH /api/v1/users/:user_id - Update user details (admin or self)
#[derive(Deserialize)]
struct UpdateUserRequest {
    username: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
}

#[derive(Serialize)]
struct UpdateUserResponse {
    user_id: i32,
    username: String,
    email: String,
    phone: String,
    first_name: String,
    last_name: String,
    updated_at: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id))]
pub async fn update_user(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path(user_id): Path<i32>,
    Json(request): Json<UpdateUserRequest>,
) -> Result<Json<UpdateUserResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Updating user user_id: {} by user_id: {}", user_id, auth_user.user_id);
    tracing::Span::current().record("user_id", &auth_user.user_id);

    // Check permissions: Either self-update or admin with update permission
    let is_self = auth_user.user_id == user_id;
    let has_admin_permission = sqlx::query_scalar!(
        r#"
        SELECT 1
        FROM permissions p
        JOIN users u ON u.role_id = p.role_id
        WHERE u.user_id = $1 AND p.api_endpoint = '/api/v1/users' AND p.permission_type = 'update'
        "#,
        auth_user.user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking permissions: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if !is_self && !has_admin_permission {
        error!("User {} lacks permission to update user_id: {}", auth_user.user_id, user_id);
        return Err((StatusCode::FORBIDDEN, "User lacks permission to update this user".to_string()));
    }

    // Validate request data (if provided)
    if let Some(ref username) = request.username {
        if username.trim().is_empty() {
            error!("Invalid username: cannot be empty");
            return Err((StatusCode::BAD_REQUEST, "Username cannot be empty".to_string()));
        }
    }
    if let Some(ref email) = request.email {
        if !email.contains('@') || email.trim().is_empty() {
            error!("Invalid email: {}", email);
            return Err((StatusCode::BAD_REQUEST, "Invalid email address".to_string()));
        }
    }
    if let Some(ref phone) = request.phone {
        if phone.trim().is_empty() || !phone.chars().all(|c| c.is_digit(10) || c == '+' || c == '-') {
            error!("Invalid phone number: {}", phone);
            return Err((StatusCode::BAD_REQUEST, "Invalid phone number".to_string()));
        }
    }
    if let Some(ref first_name) = request.first_name {
        if first_name.trim().is_empty() {
            error!("Invalid first name: cannot be empty");
            return Err((StatusCode::BAD_REQUEST, "First name cannot be empty".to_string()));
        }
    }
    if let Some(ref last_name) = request.last_name {
        if last_name.trim().is_empty() {
            error!("Invalid last name: cannot be empty");
            return Err((StatusCode::BAD_REQUEST, "Last name cannot be empty".to_string()));
        }
    }

    // Check for duplicate username, email, or phone (excluding self)
    if let Some(ref username) = request.username {
        let username_taken = sqlx::query_scalar!(
            "SELECT 1 FROM users WHERE username = $1 AND user_id != $2",
            username,
            user_id
        )
        .fetch_optional(&pool)
        .await
        .map_err(|e| { error!("Database error checking username: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
        .is_some();
        if username_taken {
            error!("Username '{}' already in use", username);
            return Err((StatusCode::CONFLICT, format!("Username '{}' already in use", username)));
        }
    }
    if let Some(ref email) = request.email {
        let email_taken = sqlx::query_scalar!(
            "SELECT 1 FROM users WHERE email = $1 AND user_id != $2",
            email,
            user_id
        )
        .fetch_optional(&pool)
        .await
        .map_err(|e| { error!("Database error checking email: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
        .is_some();
        if email_taken {
            error!("Email '{}' already in use", email);
            return Err((StatusCode::CONFLICT, format!("Email '{}' already in use", email)));
        }
    }
    if let Some(ref phone) = request.phone {
        let phone_taken = sqlx::query_scalar!(
            "SELECT 1 FROM users WHERE phone = $1 AND user_id != $2",
            phone,
            user_id
        )
        .fetch_optional(&pool)
        .await
        .map_err(|e| { error!("Database error checking phone: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
        .is_some();
        if phone_taken {
            error!("Phone '{}' already in use", phone);
            return Err((StatusCode::CONFLICT, format!("Phone '{}' already in use", phone)));
        }
    }

    // Check if user exists
    let user_exists = sqlx::query!(
        "SELECT 1 FROM users WHERE user_id = $1",
        user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking user: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if !user_exists {
        error!("User user_id: {} not found", user_id);
        return Err((StatusCode::NOT_FOUND, "User not found".to_string()));
    }

    // Update user details
    let updated_user = sqlx::query_as!(
        UpdateUserResponse,
        r#"
        UPDATE users
        SET 
            username = COALESCE($1, username),
            email = COALESCE($2, email),
            phone = COALESCE($3, phone),
            first_name = COALESCE($4, first_name),
            last_name = COALESCE($5, last_name),
            updated_at = NOW()
        WHERE user_id = $6
        RETURNING user_id, username, email, phone, first_name, last_name, updated_at
        "#,
        request.username,
        request.email,
        request.phone,
        request.first_name,
        request.last_name,
        user_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error updating user: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    info!("User updated: user_id={} by user_id: {}", user_id, auth_user.user_id);
    Ok(Json(updated_user))
}

// Endpoint: DELETE /api/v1/users/:user_id - Delete a user (admin-only)
#[derive(Serialize)]
struct DeleteUserResponse {
    message: String,
}

#[instrument(skip(pool), fields(user_id))]
pub async fn delete_user(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path(user_id): Path<i32>,
) -> Result<Json<DeleteUserResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Deleting user user_id: {} by user_id: {}", user_id, auth_user.user_id);
    tracing::Span::current().record("user_id", &auth_user.user_id);

    // Check if user has platform-wide delete permission
    let has_permission = sqlx::query_scalar!(
        r#"
        SELECT 1
        FROM permissions p
        JOIN users u ON u.role_id = p.role_id
        WHERE u.user_id = $1 AND p.api_endpoint = '/api/v1/users' AND p.permission_type = 'delete'
        "#,
        auth_user.user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking permissions: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if !has_permission {
        error!("User {} lacks delete permission for /api/v1/users", auth_user.user_id);
        return Err((StatusCode::FORBIDDEN, "User lacks permission to delete users".to_string()));
    }

    // Check if user exists
    let user_exists = sqlx::query!(
        "SELECT 1 FROM users WHERE user_id = $1",
        user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking user: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if !user_exists {
        error!("User user_id: {} not found", user_id);
        return Err((StatusCode::NOT_FOUND, "User not found".to_string()));
    }

    // Check if user has active ROSCA memberships or financial obligations
    let has_memberships = sqlx::query_scalar!(
        "SELECT 1 FROM rosca_members WHERE user_id = $1",
        user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking memberships: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    let has_contributions = sqlx::query_scalar!(
        "SELECT 1 FROM contributions WHERE user_id = $1 AND status = 'completed'",
        user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking contributions: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    let has_loans = sqlx::query_scalar!(
        "SELECT 1 FROM loans WHERE user_id = $1 AND status = 'active'",
        user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking loans: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if has_memberships || has_contributions || has_loans {
        error!("User user_id: {} has active ROSCA memberships or financial obligations", user_id);
        return Err((StatusCode::BAD_REQUEST, "User has active ROSCA memberships or financial obligations".to_string()));
    }

    // Delete the user
    let result = sqlx::query!(
        "DELETE FROM users WHERE user_id = $1 RETURNING user_id",
        user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error deleting user: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    if result.is_none() {
        error!("User user_id: {} not found during deletion", user_id);
        return Err((StatusCode::NOT_FOUND, "User not found".to_string()));
    }

    info!("User deleted: user_id={} by user_id: {}", user_id, auth_user.user_id);
    Ok(Json(DeleteUserResponse {
        message: "User deleted successfully".to_string(),
    }))
}

// Endpoint: GET /api/v1/users/me/reports - Get user's reports
#[derive(Deserialize)]
struct ReportsFilter {
    rosca_name: Option<String>, 
    start_date: Option<DateTime<Utc>>, 
    end_date: Option<DateTime<Utc>>,
    limit: Option<i32>,
    offset: Option<i32>,
}

#[derive(Serialize)]
struct UserReport {
    report_type: String, // e.g., "contributions", "loans"
    data: serde_json::Value, // JSON blob for report data
    generated_at: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id))]
pub async fn get_user_reports(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Query(filter): Query<ReportsFilter>,
) -> Result<Json<Vec<UserReport>>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Fetching reports for user_id: {}", auth_user.user_id);
    tracing::Span::current().record("user_id", &auth_user.user_id);

    // Apply filters for reports
    let limit = filter.limit.unwrap_or(50).max(1).min(100);
    let offset = filter.offset.unwrap_or(0).max(0);
    let rosca_name = filter.rosca_name;
    let start_date = filter.start_date;
    let end_date = filter.end_date;

    // Build base conditions for contributions and loans queries
    let mut conditions = vec!["c.user_id = $1"];
    let mut params: Vec<&(dyn sqlx::Encode<'_, sqlx::Postgres> + sqlx::Type<sqlx::Postgres> + Sync)> = vec![&auth_user.user_id];
    let mut param_index = 2;

    if let Some(ref name) = rosca_name {
        conditions.push(format!("r.name = ${}", param_index));
        params.push(name);
        param_index += 1;
    }
    if let Some(start) = start_date {
        conditions.push(format!("c.paid_at >= ${}", param_index));
        params.push(&start);
        param_index += 1;
    }
    if let Some(end) = end_date {
        conditions.push(format!("c.paid_at <= ${}", param_index));
        params.push(&end);
        param_index += 1;
    }
    conditions.push("c.status = 'completed'".to_string());

    // Fetch user's contributions report
    let contributions_query = format!(
        r#"
        SELECT 
            SUM(c.amount) as total_amount,
            COUNT(*) as contribution_count,
            json_agg(json_build_object(
                'rosca_name', r.name,
                'amount', c.amount,
                'cycle_number', c.cycle_number,
                'status', c.status,
                'paid_at', c.paid_at
            )) as details
        FROM contributions c
        JOIN roscas r ON c.rosca_id = r.rosca_id
        WHERE {}
        "#,
        conditions.join(" AND ")
    );
    let contributions = sqlx::query_with(
        &contributions_query,
        params.clone()
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error fetching contributions: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    let contributions_report = UserReport {
        report_type: "contributions".to_string(),
        data: serde_json::json!({
            "total_amount": contributions.total_amount.unwrap_or(0.0),
            "contribution_count": contributions.contribution_count.unwrap_or(0),
            "details": contributions.details.unwrap_or(serde_json::json!([]))
        }),
        generated_at: chrono::Utc::now(),
    };

    // Adjust conditions for loans (reuse rosca_name, adjust for disbursed_at)
    let mut loan_conditions = vec!["l.user_id = $1"];
    let mut loan_params: Vec<&(dyn sqlx::Encode<'_, sqlx::Postgres> + sqlx::Type<sqlx::Postgres> + Sync)> = vec![&auth_user.user_id];
    let mut loan_param_index = 2;

    if let Some(ref name) = rosca_name {
        loan_conditions.push(format!("r.name = ${}", loan_param_index));
        loan_params.push(name);
        loan_param_index += 1;
    }
    if let Some(start) = start_date {
        loan_conditions.push(format!("l.disbursed_at >= ${}", loan_param_index));
        loan_params.push(&start);
        loan_param_index += 1;
    }
    if let Some(end) = end_date {
        loan_conditions.push(format!("l.disbursed_at <= ${}", loan_param_index));
        loan_params.push(&end);
        loan_param_index += 1;
    }
    loan_conditions.push("l.disbursement_status = 'completed'".to_string());

    // Fetch user's loans report
    let loans_query = format!(
        r#"
        SELECT 
            SUM(l.amount) as total_disbursed,
            COUNT(*) as loan_count,
            json_agg(json_build_object(
                'rosca_name', r.name,
                'amount', l.amount,
                'interest_rate', l.interest_rate,
                'status', l.status,
                'disbursed_at', l.disbursed_at
            )) as details
        FROM loans l
        JOIN roscas r ON l.rosca_id = r.rosca_id
        WHERE {}
        "#,
        loan_conditions.join(" AND ")
    );
    let loans = sqlx::query_with(
        &loans_query,
        loan_params
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error fetching loans: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    let loans_report = UserReport {
        report_type: "loans".to_string(),
        data: serde_json::json!({
            "total_disbursed": loans.total_disbursed.unwrap_or(0.0),
            "loan_count": loans.loan_count.unwrap_or(0),
            "details": loans.details.unwrap_or(serde_json::json!([]))
        }),
        generated_at: chrono::Utc::now(),
    };

    // Combine reports with pagination
    let mut reports = vec![contributions_report, loans_report];
    let total_reports = reports.len();
    reports = reports
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect();

    info!("Retrieved {} reports (out of {}) for user_id: {}", reports.len(), total_reports, auth_user.user_id);
    Ok(Json(reports))
}

// Endpoint: GET /api/v1/users/me/analytics - Get user's analytics
#[derive(Deserialize)]
struct AnalyticsFilter {
    start_time: Option<DateTime<Utc>>,
    end_time: Option<DateTime<Utc>>,
    metric: Option<String>, // e.g., "contribution_trends"
}

#[derive(Serialize)]
struct UserAnalytics {
    metric: String,
    data: serde_json::Value, // JSON blob for analytics data
}

#[instrument(skip(pool), fields(user_id))]
pub async fn get_user_analytics(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Query(filter): Query<AnalyticsFilter>,
) -> Result<Json<Vec<UserAnalytics>>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Fetching analytics for user_id: {}", auth_user.user_id);
    tracing::Span::current().record("user_id", &auth_user.user_id);

    // Apply filters for analytics
    let start_time = filter.start_time;
    let end_time = filter.end_time;
    let metric = filter.metric.unwrap_or("contribution_trends".to_string());

    // Validate metric
    let valid_metrics = vec!["contribution_trends", "loan_activity", "payout_trends"];
    if !valid_metrics.contains(&metric.as_str()) {
        error!("Invalid metric: {}", metric);
        return Err((StatusCode::BAD_REQUEST, format!("Invalid metric. Supported metrics: {:?}", valid_metrics)));
    }

    // Build base conditions
    let mut conditions = vec!["user_id = $1"];
    let mut params: Vec<&(dyn sqlx::Encode<'_, sqlx::Postgres> + sqlx::Type<sqlx::Postgres> + Sync)> = vec![&auth_user.user_id];
    let mut param_index = 2;

    // Fetch analytics based on metric
    let analytics = match metric.as_str() {
        "contribution_trends" => {
            if let Some(start) = start_time {
                conditions.push(format!("paid_at >= ${}", param_index));
                params.push(&start);
                param_index += 1;
            }
            if let Some(end) = end_time {
                conditions.push(format!("paid_at <= ${}", param_index));
                params.push(&end);
                param_index += 1;
            }
            conditions.push("status = 'completed'".to_string());

            let query = format!(
                r#"
                SELECT 
                    SUM(amount) as total_contributions,
                    COUNT(*) as contribution_count,
                    AVG(amount) as avg_contribution,
                    json_agg(json_build_object(
                        'rosca_name', r.name,
                        'amount', c.amount,
                        'cycle_number', c.cycle_number,
                        'paid_at', c.paid_at
                    )) as details
                FROM contributions c
                JOIN roscas r ON c.rosca_id = r.rosca_id
                WHERE {}
                "#,
                conditions.join(" AND ")
            );
            let result = sqlx::query_with(&query, params)
                .fetch_one(&pool)
                .await
                .map_err(|e| { error!("Database error fetching contribution trends: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

            UserAnalytics {
                metric: "contribution_trends".to_string(),
                data: serde_json::json!({
                    "total_contributions": result.total_contributions.unwrap_or(0.0),
                    "contribution_count": result.contribution_count.unwrap_or(0),
                    "avg_contribution": result.avg_contribution.unwrap_or(0.0),
                    "details": result.details.unwrap_or(serde_json::json!([]))
                }),
            }
        },
        "loan_activity" => {
            if let Some(start) = start_time {
                conditions.push(format!("disbursed_at >= ${}", param_index));
                params.push(&start);
                param_index += 1;
            }
            if let Some(end) = end_time {
                conditions.push(format!("disbursed_at <= ${}", param_index));
                params.push(&end);
                param_index += 1;
            }
            conditions.push("disbursement_status = 'completed'".to_string());

            let query = format!(
                r#"
                SELECT 
                    SUM(amount) as total_loans,
                    COUNT(*) as loan_count,
                    AVG(interest_rate) as avg_interest_rate,
                    json_agg(json_build_object(
                        'rosca_name', r.name,
                        'amount', l.amount,
                        'interest_rate', l.interest_rate,
                        'disbursed_at', l.disbursed_at
                    )) as details
                FROM loans l
                JOIN roscas r ON l.rosca_id = r.rosca_id
                WHERE {}
                "#,
                conditions.join(" AND ")
            );
            let result = sqlx::query_with(&query, params)
                .fetch_one(&pool)
                .await
                .map_err(|e| { error!("Database error fetching loan activity: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

            UserAnalytics {
                metric: "loan_activity".to_string(),
                data: serde_json::json!({
                    "total_loans": result.total_loans.unwrap_or(0.0),
                    "loan_count": result.loan_count.unwrap_or(0),
                    "avg_interest_rate": result.avg_interest_rate.unwrap_or(0.0),
                    "details": result.details.unwrap_or(serde_json::json!([]))
                }),
            }
        },
        "payout_trends" => {
            if let Some(start) = start_time {
                conditions.push(format!("payout_at >= ${}", param_index));
                params.push(&start);
                param_index += 1;
            }
            if let Some(end) = end_time {
                conditions.push(format!("payout_at <= ${}", param_index));
                params.push(&end);
                param_index += 1;
            }
            conditions.push("payout_status = 'completed'".to_string());

            let query = format!(
                r#"
                SELECT 
                    SUM(amount) as total_payouts,
                    COUNT(*) as payout_count,
                    AVG(amount) as avg_payout,
                    json_agg(json_build_object(
                        'rosca_name', r.name,
                        'amount', p.amount,
                        'cycle_number', p.cycle_number,
                        'payout_at', p.payout_at
                    )) as details
                FROM payouts p
                JOIN roscas r ON p.rosca_id = r.rosca_id
                WHERE {}
                "#,
                conditions.join(" AND ")
            );
            let result = sqlx::query_with(&query, params)
                .fetch_one(&pool)
                .await
                .map_err(|e| { error!("Database error fetching payout trends: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

            UserAnalytics {
                metric: "payout_trends".to_string(),
                data: serde_json::json!({
                    "total_payouts": result.total_payouts.unwrap_or(0.0),
                    "payout_count": result.payout_count.unwrap_or(0),
                    "avg_payout": result.avg_payout.unwrap_or(0.0),
                    "details": result.details.unwrap_or(serde_json::json!([]))
                }),
            }
        },
        _ => unreachable!(), // Validated above
    };

    info!("Retrieved analytics for metric '{}' for user_id: {}", metric, auth_user.user_id);
    Ok(Json(vec![analytics]))
}

// Endpoint: GET /api/v1/users/me/notifications - Get user's notifications
#[derive(Deserialize)]
struct NotificationsFilter {
    status: Option<String>,
    limit: Option<i32>,
    offset: Option<i32>,
}

#[derive(Serialize, sqlx::FromRow)]
struct UserNotification {
    notification_id: i32,
    notification_type: String,
    message: String,
    status: String,
    created_at: DateTime<Utc>,
    sent_at: Option<DateTime<Utc>>,
    read_at: Option<DateTime<Utc>>,
}

#[instrument(skip(pool), fields(user_id))]
pub async fn get_user_notifications(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Query(filter): Query<NotificationsFilter>,
) -> Result<Json<Vec<UserNotification>>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Fetching notifications for user_id: {}", auth_user.user_id);
    tracing::Span::current().record("user_id", &auth_user.user_id);

    // Apply filters for notifications
    let limit = filter.limit.unwrap_or(50).max(1).min(100);
    let offset = filter.offset.unwrap_or(0).max(0);
    let status = filter.status;

    // Build conditions and parameters
    let mut conditions = vec!["user_id = $1"];
    let mut params: Vec<&(dyn sqlx::Encode<'_, sqlx::Postgres> + sqlx::Type<sqlx::Postgres> + Sync)> = vec![&auth_user.user_id];
    let mut param_index = 2;

    if let Some(ref s) = status {
        conditions.push(format!("status = ${}", param_index));
        params.push(s);
        param_index += 1;
    }

    // Fetch user's notifications with pagination
    let query = format!(
        r#"
        SELECT 
            notification_id,
            notification_type,
            message,
            status,
            created_at,
            sent_at,
            read_at
        FROM notifications
        WHERE {}
        ORDER BY created_at DESC
        LIMIT ${} OFFSET ${}
        "#,
        conditions.join(" AND "),
        param_index,
        param_index + 1
    );
    params.push(&limit);
    params.push(&offset);

    let notifications = sqlx::query_as_with::<_, UserNotification, _>(&query, params)
        .fetch_all(&pool)
        .await
        .map_err(|e| { error!("Database error fetching notifications: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    info!("Retrieved {} notifications for user_id: {}", notifications.len(), auth_user.user_id);
    Ok(Json(notifications))
}

// Endpoint: GET /api/v1/users/me/export - Export user's data
#[derive(Deserialize)]
struct ExportFilter {
    format: Option<String>, // e.g., "csv", "json", "pdf", "excel"
    rosca_name: Option<String>, //filter by ROSCA name
    start_date: Option<DateTime<Utc>>, // start date filter
    end_date: Option<DateTime<Utc>>, // end date filter
}

#[derive(Serialize)]
struct ExportResponse {
    data: String, // Encoded data (e.g., CSV string or JSON)
    format: String,
}

#[instrument(skip(pool), fields(user_id))]
pub async fn export_user_data(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Query(filter): Query<ExportFilter>,
) -> Result<Json<ExportResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Exporting data for user_id: {}", auth_user.user_id);
    tracing::Span::current().record("user_id", &auth_user.user_id);

    // Apply filters
    let format = filter.format.unwrap_or("json".to_string()).to_lowercase();
    let rosca_name = filter.rosca_name;
    let start_date = filter.start_date;
    let end_date = filter.end_date;

    let valid_formats = vec!["csv", "json", "pdf", "excel"];
    if !valid_formats.contains(&format.as_str()) {
        error!("Invalid format: {}", format);
        return Err((StatusCode::BAD_REQUEST, format!("Invalid format. Supported formats: {:?}", valid_formats)));
    }

    // Fetch user profile (not filtered by ROSCA or dates)
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
    .map_err(|e| { error!("Database error fetching profile: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    // Build conditions for contributions, loans, and payouts
    let mut conditions = vec!["c.user_id = $1"];
    let mut params: Vec<&(dyn sqlx::Encode<'_, sqlx::Postgres> + sqlx::Type<sqlx::Postgres> + Sync)> = vec![&auth_user.user_id];
    let mut param_index = 2;

    if let Some(ref name) = rosca_name {
        conditions.push(format!("r.name = ${}", param_index));
        params.push(name);
        param_index += 1;
    }
    if let Some(start) = start_date {
        conditions.push(format!("c.paid_at >= ${}", param_index));
        params.push(&start);
        param_index += 1;
    }
    if let Some(end) = end_date {
        conditions.push(format!("c.paid_at <= ${}", param_index));
        params.push(&end);
        param_index += 1;
    }

    // Fetch user's contributions with filters
    let contributions_query = format!(
        r#"
        SELECT r.name as rosca_name, amount, cycle_number, status, paid_at
        FROM contributions c
        JOIN roscas r ON c.rosca_id = r.rosca_id
        WHERE {}
        ORDER BY paid_at
        "#,
        conditions.join(" AND ")
    );
    let contributions = sqlx::query_with(&contributions_query, params.clone())
        .fetch_all(&pool)
        .await
        .map_err(|e| { error!("Database error fetching contributions: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    // Adjust conditions for loans
    let mut loan_conditions = vec!["l.user_id = $1"];
    let mut loan_params: Vec<&(dyn sqlx::Encode<'_, sqlx::Postgres> + sqlx::Type<sqlx::Postgres> + Sync)> = vec![&auth_user.user_id];
    let mut loan_param_index = 2;

    if let Some(ref name) = rosca_name {
        loan_conditions.push(format!("r.name = ${}", loan_param_index));
        loan_params.push(name);
        loan_param_index += 1;
    }
    if let Some(start) = start_date {
        loan_conditions.push(format!("l.disbursed_at >= ${}", loan_param_index));
        loan_params.push(&start);
        loan_param_index += 1;
    }
    if let Some(end) = end_date {
        loan_conditions.push(format!("l.disbursed_at <= ${}", loan_param_index));
        loan_params.push(&end);
        loan_param_index += 1;
    }

    let loans_query = format!(
        r#"
        SELECT r.name as rosca_name, amount, interest_rate, status, disbursement_status, disbursed_at
        FROM loans l
        JOIN roscas r ON l.rosca_id = r.rosca_id
        WHERE {}
        ORDER BY disbursed_at
        "#,
        loan_conditions.join(" AND ")
    );
    let loans = sqlx::query_with(&loans_query, loan_params)
        .fetch_all(&pool)
        .await
        .map_err(|e| { error!("Database error fetching loans: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    // Adjust conditions for payouts
    let mut payout_conditions = vec!["p.user_id = $1"];
    let mut payout_params: Vec<&(dyn sqlx::Encode<'_, sqlx::Postgres> + sqlx::Type<sqlx::Postgres> + Sync)> = vec![&auth_user.user_id];
    let mut payout_param_index = 2;

    if let Some(ref name) = rosca_name {
        payout_conditions.push(format!("r.name = ${}", payout_param_index));
        payout_params.push(name);
        payout_param_index += 1;
    }
    if let Some(start) = start_date {
        payout_conditions.push(format!("p.payout_at >= ${}", payout_param_index));
        payout_params.push(&start);
        payout_param_index += 1;
    }
    if let Some(end) = end_date {
        payout_conditions.push(format!("p.payout_at <= ${}", payout_param_index));
        payout_params.push(&end);
        payout_param_index += 1;
    }

    let payouts_query = format!(
        r#"
        SELECT r.name as rosca_name, amount, cycle_number, payout_status, payout_at
        FROM payouts p
        JOIN roscas r ON p.rosca_id = r.rosca_id
        WHERE {}
        ORDER BY payout_at
        "#,
        payout_conditions.join(" AND ")
    );
    let payouts = sqlx::query_with(&payouts_query, payout_params)
        .fetch_all(&pool)
        .await
        .map_err(|e| { error!("Database error fetching payouts: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    // Construct the export data
    let export_data = match format.as_str() {
        "json" => {
            let json_data = serde_json::json!({
                "profile": {
                    "username": profile.username,
                    "email": profile.email,
                    "phone": profile.phone,
                    "first_name": profile.first_name,
                    "last_name": profile.last_name,
                    "created_at": profile.created_at,
                    "updated_at": profile.updated_at
                },
                "contributions": contributions.into_iter().map(|c| serde_json::json!({
                    "rosca_name": c.rosca_name,
                    "amount": c.amount,
                    "cycle_number": c.cycle_number,
                    "status": c.status,
                    "paid_at": c.paid_at
                })).collect::<Vec<_>>(),
                "loans": loans.into_iter().map(|l| serde_json::json!({
                    "rosca_name": l.rosca_name,
                    "amount": l.amount,
                    "interest_rate": l.interest_rate,
                    "status": l.status,
                    "disbursement_status": l.disbursement_status,
                    "disbursed_at": l.disbursed_at
                })).collect::<Vec<_>>(),
                "payouts": payouts.into_iter().map(|p| serde_json::json!({
                    "rosca_name": p.rosca_name,
                    "amount": p.amount,
                    "cycle_number": p.cycle_number,
                    "payout_status": p.payout_status,
                    "payout_at": p.payout_at
                })).collect::<Vec<_>>()
            });
            serde_json::to_string(&json_data)
                .map_err(|e| { error!("JSON serialization error: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
        },
        "csv" => {
            let mut wtr = csv::WriterBuilder::new()
                .delimiter(b',')
                .from_writer(vec![]);

            // Profile headers and data (no date filtering applies)
            wtr.write_record(&["section", "username", "email", "phone", "first_name", "last_name", "created_at", "updated_at"])?;
            wtr.write_record(&[
                "profile",
                &profile.username,
                &profile.email,
                &profile.phone,
                &profile.first_name,
                &profile.last_name,
                &profile.created_at.to_rfc3339(),
                &profile.updated_at.to_rfc3339(),
            ])?;

            // Contributions headers and data
            wtr.write_record(&["section", "rosca_name", "amount", "cycle_number", "status", "paid_at"])?;
            for c in contributions {
                wtr.write_record(&[
                    "contributions",
                    &c.rosca_name,
                    &c.amount.to_string(),
                    &c.cycle_number.to_string(),
                    &c.status,
                    &c.paid_at.map(|d| d.to_rfc3339()).unwrap_or_default(),
                ])?;
            }

            // Loans headers and data
            wtr.write_record(&["section", "rosca_name", "amount", "interest_rate", "status", "disbursement_status", "disbursed_at"])?;
            for l in loans {
                wtr.write_record(&[
                    "loans",
                    &l.rosca_name,
                    &l.amount.to_string(),
                    &l.interest_rate.to_string(),
                    &l.status,
                    &l.disbursement_status,
                    &l.disbursed_at.map(|d| d.to_rfc3339()).unwrap_or_default(),
                ])?;
            }

            // Payouts headers and data
            wtr.write_record(&["section", "rosca_name", "amount", "cycle_number", "payout_status", "payout_at"])?;
            for p in payouts {
                wtr.write_record(&[
                    "payouts",
                    &p.rosca_name,
                    &p.amount.to_string(),
                    &p.cycle_number.to_string(),
                    &p.payout_status,
                    &p.payout_at.map(|d| d.to_rfc3339()).unwrap_or_default(),
                ])?;
            }

            String::from_utf8(wtr.into_inner()
                .map_err(|e| { error!("CSV serialization error: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?)
                .map_err(|e| { error!("UTF-8 conversion error: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
        },
        "pdf" => {
            let mut doc = pdf::Document::new("User Data Export");
            doc.add_page(pdf::Page::new(pdf::A4));

            let mut content = String::new();
            content.push_str(&format!("User Profile\n\nUsername: {}\nEmail: {}\nPhone: {}\nFirst Name: {}\nLast Name: {}\nCreated At: {}\nUpdated At: {}\n\n",
                profile.username, profile.email, profile.phone, profile.first_name, profile.last_name,
                profile.created_at.to_rfc3339(), profile.updated_at.to_rfc3339()));

            content.push_str("Contributions\n\n");
            for c in &contributions {
                content.push_str(&format!("Rosca: {}, Amount: {}, Cycle: {}, Status: {}, Paid At: {}\n",
                    c.rosca_name, c.amount, c.cycle_number, c.status,
                    c.paid_at.map(|d| d.to_rfc3339()).unwrap_or_default()));
            }

            content.push_str("\nLoans\n\n");
            for l in &loans {
                content.push_str(&format!("Rosca: {}, Amount: {}, Interest Rate: {}, Status: {}, Disbursement Status: {}, Disbursed At: {}\n",
                    l.rosca_name, l.amount, l.interest_rate, l.status, l.disbursement_status,
                    l.disbursed_at.map(|d| d.to_rfc3339()).unwrap_or_default()));
            }

            content.push_str("\nPayouts\n\n");
            for p in &payouts {
                content.push_str(&format!("Rosca: {}, Amount: {}, Cycle: {}, Status: {}, Payout At: {}\n",
                    p.rosca_name, p.amount, p.cycle_number, p.payout_status,
                    p.payout_at.map(|d| d.to_rfc3339()).unwrap_or_default()));
            }

            doc.add_text(content, 12.0, pdf::Font::Helvetica);
            let pdf_data = doc.render()
                .map_err(|e| { error!("PDF rendering error: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;
            base64::encode(&pdf_data)
        },
        "excel" => {
            let mut wb = xlsx::Workbook::new();
            let mut ws = wb.add_worksheet("User Data");

            // Profile headers and data
            let headers = vec!["Section", "Username", "Email", "Phone", "First Name", "Last Name", "Created At", "Updated At"];
            for (col, header) in headers.iter().enumerate() {
                ws.write_string(0, col as u16, header)?;
            }
            ws.write_string(1, 0, "Profile")?;
            ws.write_string(1, 1, &profile.username)?;
            ws.write_string(1, 2, &profile.email)?;
            ws.write_string(1, 3, &profile.phone)?;
            ws.write_string(1, 4, &profile.first_name)?;
            ws.write_string(1, 5, &profile.last_name)?;
            ws.write_string(1, 6, &profile.created_at.to_rfc3339())?;
            ws.write_string(1, 7, &profile.updated_at.to_rfc3339())?;

            // Contributions headers and data
            let contrib_headers = vec!["Section", "Rosca Name", "Amount", "Cycle Number", "Status", "Paid At"];
            for (col, header) in contrib_headers.iter().enumerate() {
                ws.write_string(3, col as u16, header)?;
            }
            for (row, c) in contributions.iter().enumerate() {
                let row = row as u32 + 4;
                ws.write_string(row, 0, "Contributions")?;
                ws.write_string(row, 1, &c.rosca_name)?;
                ws.write_number(row, 2, c.amount)?;
                ws.write_number(row, 3, c.cycle_number as f64)?;
                ws.write_string(row, 4, &c.status)?;
                ws.write_string(row, 5, &c.paid_at.map(|d| d.to_rfc3339()).unwrap_or_default())?;
            }

            // Loans headers and data
            let loan_headers = vec!["Section", "Rosca Name", "Amount", "Interest Rate", "Status", "Disbursement Status", "Disbursed At"];
            let loan_start_row = contributions.len() as u32 + 6;
            for (col, header) in loan_headers.iter().enumerate() {
                ws.write_string(loan_start_row, col as u16, header)?;
            }
            for (row, l) in loans.iter().enumerate() {
                let row = loan_start_row + 1 + row as u32;
                ws.write_string(row, 0, "Loans")?;
                ws.write_string(row, 1, &l.rosca_name)?;
                ws.write_number(row, 2, l.amount)?;
                ws.write_number(row, 3, l.interest_rate)?;
                ws.write_string(row, 4, &l.status)?;
                ws.write_string(row, 5, &l.disbursement_status)?;
                ws.write_string(row, 6, &l.disbursed_at.map(|d| d.to_rfc3339()).unwrap_or_default())?;
            }

            // Payouts headers and data
            let payout_headers = vec!["Section", "Rosca Name", "Amount", "Cycle Number", "Payout Status", "Payout At"];
            let payout_start_row = loan_start_row + loans.len() as u32 + 2;
            for (col, header) in payout_headers.iter().enumerate() {
                ws.write_string(payout_start_row, col as u16, header)?;
            }
            for (row, p) in payouts.iter().enumerate() {
                let row = payout_start_row + 1 + row as u32;
                ws.write_string(row, 0, "Payouts")?;
                ws.write_string(row, 1, &p.rosca_name)?;
                ws.write_number(row, 2, p.amount)?;
                ws.write_number(row, 3, p.cycle_number as f64)?;
                ws.write_string(row, 4, &p.payout_status)?;
                ws.write_string(row, 5, &p.payout_at.map(|d| d.to_rfc3339()).unwrap_or_default())?;
            }

            let excel_data = wb.close()
                .map_err(|e| { error!("Excel serialization error: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;
            base64::encode(&excel_data)
        },
        _ => unreachable!(), // Validated above
    };

    info!("Data exported in {} format for user_id: {}", format, auth_user.user_id);
    Ok(Json(ExportResponse {
        data: export_data,
        format,
    }))
}

// Endpoint: GET /api/v1/users/me/forecast - Get user's forecast
#[derive(Deserialize)]
struct ForecastFilter {
    horizon: Option<i32>, // Number of future periods
    granularity: Option<String>, // e.g., "monthly"
}

#[derive(Serialize)]
struct UserForecast {
    period: String,
    projected_contributions: f64,
    projected_payouts: f64,
}

#[instrument(skip(pool), fields(user_id))]
pub async fn get_user_forecast(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Query(filter): Query<ForecastFilter>,
) -> Result<Json<Vec<UserForecast>>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Fetching forecast for user_id: {}", auth_user.user_id);
    tracing::Span::current().record("user_id", &auth_user.user_id);

    // Apply filters for forecast
    let horizon = filter.horizon.unwrap_or(6).max(1).min(12); // Default 6 periods, max 12
    let granularity = filter.granularity.unwrap_or("monthly".to_string()).to_lowercase();
    let valid_granularities = vec!["daily", "monthly", "yearly"];
    if !valid_granularities.contains(&granularity.as_str()) {
        error!("Invalid granularity: {}", granularity);
        return Err((StatusCode::BAD_REQUEST, format!("Invalid granularity. Supported: {:?}", valid_granularities)));
    }

    // Fetch user's current contribution trends
    let contributions = sqlx::query!(
        r#"
        SELECT 
            r.name as rosca_name,
            AVG(c.amount) as avg_amount,
            COUNT(*) as contribution_count,
            MAX(c.paid_at) as last_paid_at
        FROM contributions c
        JOIN roscas r ON c.rosca_id = r.rosca_id
        WHERE c.user_id = $1 AND c.status = 'completed'
        GROUP BY r.rosca_id, r.name
        "#,
        auth_user.user_id
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| { error!("Database error fetching contributions: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    // Fetch user's current payout trends
    let payouts = sqlx::query!(
        r#"
        SELECT 
            r.name as rosca_name,
            AVG(p.amount) as avg_amount,
            COUNT(*) as payout_count,
            MAX(p.payout_at) as last_payout_at
        FROM payouts p
        JOIN roscas r ON p.rosca_id = r.rosca_id
        WHERE p.user_id = $1 AND p.payout_status = 'completed'
        GROUP BY r.rosca_id, r.name
        "#,
        auth_user.user_id
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| { error!("Database error fetching payouts: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    // Generate forecast based on granularity
    let now = chrono::Utc::now();
    let mut forecast = Vec::new();

    let period_duration = match granularity.as_str() {
        "daily" => chrono::Duration::days(1),
        "monthly" => chrono::Duration::days(30), // Approximate month
        "yearly" => chrono::Duration::days(365), // Approximate year
        _ => unreachable!(), // Validated above
    };
    let period_format = match granularity.as_str() {
        "daily" => "%Y-%m-%d",
        "monthly" => "%Y-%m",
        "yearly" => "%Y",
        _ => unreachable!(),
    };

    for i in 0..horizon {
        let period_date = now + period_duration * i as i32;
        let period = period_date.format(period_format).to_string();

        // Forecast contributions
        let mut projected_contributions = 0.0;
        for contrib in &contributions {
            // Simple assumption: Continue average contribution if active in ROSCA
            if contrib.contribution_count > 0 {
                projected_contributions += contrib.avg_amount.unwrap_or(0.0);
            }
        }

        // Forecast payouts
        let mut projected_payouts = 0.0;
        for payout in &payouts {
            // Simple assumption: Continue average payout if active in ROSCA
            if payout.payout_count > 0 {
                projected_payouts += payout.avg_amount.unwrap_or(0.0);
            }
        }

        forecast.push(UserForecast {
            period,
            projected_contributions,
            projected_payouts,
        });
    }

    info!("Generated forecast with {} periods ({} granularity) for user_id: {}", forecast.len(), granularity, auth_user.user_id);
    Ok(Json(forecast))
}

// Endpoint: GET /api/v1/users/me/simulation - Simulate user's data
#[derive(Deserialize)]
struct SimulationFilter {
    horizon: Option<i32>, // Number of periods
    contribution_increase: Option<f64>, // Percentage increase per period
    absolute_contribution_amount: Option<f64>, // Absolute contribution amount per period
    cycle_type: Option<String>, // "daily", "monthly", "yearly"
    cycle_length: Option<i32>, // Custom cycle length in days
    payout_cycle: Option<i32>, // Optional payout cycle override
}

#[derive(Serialize)]
struct UserSimulation {
    period: String,
    projected_contributions: f64,
    projected_loans: f64,
    projected_payouts: f64,
}

#[instrument(skip(pool), fields(user_id))]
pub async fn simulate_user_data(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Query(filter): Query<SimulationFilter>,
) -> Result<Json<Vec<UserSimulation>>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Simulating data for user_id: {}", auth_user.user_id);
    tracing::Span::current().record("user_id", &auth_user.user_id);

    // Apply filters for simulation
    let horizon = filter.horizon.unwrap_or(6).max(1).min(12); // Default 6 periods, max 12
    let contribution_increase = filter.contribution_increase.unwrap_or(0.0).max(-0.5).min(0.5); // -50% to +50%
    let absolute_contribution_amount = filter.absolute_contribution_amount.filter(|&v| v > 0.0); // Optional absolute amount
    let cycle_type = filter.cycle_type.unwrap_or("monthly".to_string()).to_lowercase();
    let cycle_length = filter.cycle_length.unwrap_or(30).max(1).min(365); // Default 30 days, range 1-365
    let payout_cycle = filter.payout_cycle.unwrap_or(None); // Optional payout cycle override

    let valid_cycle_types = vec!["daily", "monthly", "yearly"];
    if !valid_cycle_types.contains(&cycle_type.as_str()) {
        error!("Invalid cycle type: {}", cycle_type);
        return Err((StatusCode::BAD_REQUEST, format!("Invalid cycle type. Supported: {:?}", valid_cycle_types)));
    }

    // Fetch user's ROSCA memberships with cycle details
    let roscas = sqlx::query!(
        r#"
        SELECT 
            r.rosca_id,
            r.name as rosca_name,
            rs.cycle_type,
            rs.cycle_length,
            rs.contribution_amount,
            (rs.payout_rules->>'payout_cycle')::INTEGER as payout_cycle
        FROM rosca_members rm
        JOIN roscas r ON rm.rosca_id = r.rosca_id
        JOIN rosca_settings rs ON r.rosca_id = rs.rosca_id
        WHERE rm.user_id = $1 AND rm.status = 'active'
        "#,
        auth_user.user_id
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| { error!("Database error fetching ROSCA memberships: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    // Fetch user's current contribution trends
    let contributions = sqlx::query!(
        r#"
        SELECT 
            r.rosca_id,
            AVG(c.amount) as avg_amount,
            COUNT(*) as contribution_count,
            MAX(c.paid_at) as last_paid_at
        FROM contributions c
        JOIN roscas r ON c.rosca_id = r.rosca_id
        WHERE c.user_id = $1 AND c.status = 'completed'
        GROUP BY r.rosca_id
        "#,
        auth_user.user_id
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| { error!("Database error fetching contributions: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    // Fetch user's current loan trends with repayment schedules
    let loans = sqlx::query!(
        r#"
        SELECT 
            l.rosca_id,
            AVG(l.amount) as avg_amount,
            AVG(l.interest_rate) as avg_interest_rate,
            AVG(l.repayment_cycles) as avg_repayment_cycles,
            COUNT(*) as loan_count,
            MAX(l.disbursed_at) as last_disbursed_at
        FROM loans l
        WHERE l.user_id = $1 AND l.disbursement_status = 'completed'
        GROUP BY l.rosca_id
        "#,
        auth_user.user_id
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| { error!("Database error fetching loans: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    // Fetch user's current payout trends and completed cycles
    let payouts = sqlx::query!(
        r#"
        SELECT 
            r.rosca_id,
            AVG(p.amount) as avg_amount,
            COUNT(*) as payout_count,
            MAX(p.payout_at) as last_payout_at,
            MAX(p.cycle_number) as max_cycle_number
        FROM payouts p
        JOIN roscas r ON p.rosca_id = r.rosca_id
        WHERE p.user_id = $1 AND p.payout_status = 'completed'
        GROUP BY r.rosca_id
        "#,
        auth_user.user_id
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| { error!("Database error fetching payouts: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    // Generate simulation
    let now = chrono::Utc::now();
    let mut simulation = Vec::new();

    // Determine period duration based on cycle_type or cycle_length
    let period_duration = match cycle_type.as_str() {
        "daily" => chrono::Duration::days(1),
        "monthly" => chrono::Duration::days(30),
        "yearly" => chrono::Duration::days(365),
        _ => chrono::Duration::days(cycle_length), // Use cycle_length if specified
    };
    let period_format = match cycle_type.as_str() {
        "daily" => "%Y-%m-%d",
        "monthly" => "%Y-%m",
        "yearly" => "%Y",
        _ => "%Y-%m-%d", // Default to daily format if custom length
    };

    for i in 0..horizon {
        let period_date = now + period_duration * i as i32;
        let period = period_date.format(period_format).to_string();

        // Simulate contributions per ROSCA
        let mut projected_contributions = 0.0;
        for rosca in &roscas {
            let contrib = contributions.iter().find(|c| c.rosca_id == rosca.rosca_id);
            let base_amount = absolute_contribution_amount
                .unwrap_or_else(|| contrib.and_then(|c| c.avg_amount).unwrap_or(rosca.contribution_amount.unwrap_or(0.0)));
            let increase_factor = if contribution_increase != 0.0 {
                1.0 + (contribution_increase * i as f64)
            } else {
                1.0
            };
            projected_contributions += base_amount * increase_factor.max(0.0); // No negative contributions
        }

        // Simulate loans with repayment schedules
        let mut projected_loans = 0.0;
        for rosca in &roscas {
            let loan = loans.iter().find(|l| l.rosca_id == rosca.rosca_id);
            if let Some(l) = loan {
                if l.loan_count > 0 && i % l.avg_repayment_cycles.unwrap_or(3.0) as i32 == 0 { // Loan every repayment cycle
                    projected_loans += l.avg_amount.unwrap_or(0.0);
                }
            }
        }

        // Simulate payouts with payout cycle
        let mut projected_payouts = 0.0;
        for rosca in &roscas {
            let payout = payouts.iter().find(|p| p.rosca_id == rosca.rosca_id);
            let effective_payout_cycle = payout_cycle
                .or(rosca.payout_cycle)
                .unwrap_or_else(|| payout.and_then(|p| p.max_cycle_number).unwrap_or(1) as i32);
            if i % effective_payout_cycle == 0 { // Payout every effective cycle
                if let Some(p) = payout {
                    if p.payout_count > 0 {
                        projected_payouts += p.avg_amount.unwrap_or(0.0);
                    }
                }
            }
        }

        simulation.push(UserSimulation {
            period,
            projected_contributions,
            projected_loans,
            projected_payouts,
        });
    }

    info!("Generated simulation with {} periods for user_id: {}", simulation.len(), auth_user.user_id);
    Ok(Json(simulation))
}
