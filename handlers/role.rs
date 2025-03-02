// src/handlers/role.rs
// Role endpoint handlers for the ROSCA Platform API

use axum::{http::{StatusCode, HeaderValue}, extract::{State, Path, Query}, Json};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{debug, error, info, instrument};
use chrono::{DateTime, Utc};
use crate::handlers::auth::extract_auth_user;

// Authentication extractor
struct AuthUser { user_id: i32; }

// Endpoint: GET /api/v1/roles - List all roles
#[derive(Deserialize)]
struct RoleFilter {
    limit: Option<i32>,
    offset: Option<i32>,
}

#[derive(Serialize, sqlx::FromRow)]
struct Role {
    role_id: i32,
    name: String,
    description: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id))]
pub async fn list_roles(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Query(filter): Query<RoleFilter>,
) -> Result<Json<Vec<Role>>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Listing all roles by user_id: {}", auth_user.user_id);
    tracing::Span::current().record("user_id", &auth_user.user_id);

    // Check if user has platform-wide read permission
    let has_permission = sqlx::query_scalar!(
        r#"
        SELECT 1
        FROM permissions p
        JOIN users u ON u.role_id = p.role_id
        WHERE u.user_id = $1 AND p.api_endpoint = '/api/v1/roles' AND p.permission_type = 'read'
        "#,
        auth_user.user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking permissions: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if !has_permission {
        error!("User {} lacks read permission for /api/v1/roles", auth_user.user_id);
        return Err((StatusCode::FORBIDDEN, "User lacks read permission".to_string()));
    }

    // Apply filters for roles
    let limit = filter.limit.unwrap_or(50).max(1).min(100);
    let offset = filter.offset.unwrap_or(0).max(0);

    // Fetch all roles with pagination
    let roles = sqlx::query_as!(
        Role,
        r#"
        SELECT 
            role_id,
            name,
            description,
            created_at,
            updated_at
        FROM roles
        ORDER BY created_at DESC
        LIMIT $1 OFFSET $2
        "#,
        limit as i64,
        offset as i64
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| { error!("Database error fetching roles: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    info!("Retrieved {} roles for user_id: {}", roles.len(), auth_user.user_id);
    Ok(Json(roles))
}

// Endpoint: POST /api/v1/roles - Create a new role
#[derive(Deserialize)]
struct CreateRoleRequest {
    name: String,
    description: Option<String>,
    permissions: Vec<String>, // List of permission strings (e.g., "read:/api/v1/users")
}

#[derive(Serialize)]
struct CreateRoleResponse {
    role_id: i32,
    name: String,
    description: Option<String>,
    created_at: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id))]
pub async fn create_role(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Json(request): Json<CreateRoleRequest>,
) -> Result<Json<CreateRoleResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Creating role by user_id: {}", auth_user.user_id);
    tracing::Span::current().record("user_id", &auth_user.user_id);

    // Check if user has platform-wide create permission
    let has_permission = sqlx::query_scalar!(
        r#"
        SELECT 1
        FROM permissions p
        JOIN users u ON u.role_id = p.role_id
        WHERE u.user_id = $1 AND p.api_endpoint = '/api/v1/roles' AND p.permission_type = 'create'
        "#,
        auth_user.user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking permissions: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if !has_permission {
        error!("User {} lacks create permission for /api/v1/roles", auth_user.user_id);
        return Err((StatusCode::FORBIDDEN, "User lacks create permission".to_string()));
    }

    // Validate request data
    if request.name.trim().is_empty() {
        error!("Role name cannot be empty");
        return Err((StatusCode::BAD_REQUEST, "Role name cannot be empty".to_string()));
    }

    // Check for duplicate role name
    let name_exists = sqlx::query_scalar!(
        "SELECT 1 FROM roles WHERE name = $1",
        request.name
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking role name: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if name_exists {
        error!("Role name '{}' already exists", request.name);
        return Err((StatusCode::CONFLICT, format!("Role name '{}' already exists", request.name)));
    }

    // Validate permissions (ensure format: "permission_type:api_endpoint")
    for perm in &request.permissions {
        let parts: Vec<&str> = perm.split(':').collect();
        if parts.len() != 2 || !["read", "create", "update", "delete"].contains(&parts[0]) || !parts[1].starts_with("/api/v1/") {
            error!("Invalid permission format: {}", perm);
            return Err((StatusCode::BAD_REQUEST, format!("Invalid permission format: '{}'. Use 'permission_type:api_endpoint'", perm)));
        }
    }

    // Create the role
    let role = sqlx::query!(
        r#"
        INSERT INTO roles (name, description)
        VALUES ($1, $2)
        RETURNING role_id, name, description, created_at
        "#,
        request.name,
        request.description
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error creating role: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    // Insert associated permissions
    for perm in &request.permissions {
        let parts: Vec<&str> = perm.split(':').collect();
        sqlx::query!(
            r#"
            INSERT INTO permissions (role_id, permission_type, api_endpoint)
            VALUES ($1, $2, $3)
            "#,
            role.role_id,
            parts[0], // permission_type (e.g., "read")
            parts[1], // api_endpoint (e.g., "/api/v1/users")
        )
        .execute(&pool)
        .await
        .map_err(|e| { error!("Database error inserting permission: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;
    }

    info!("Role created: role_id={} with name='{}' by user_id: {}", role.role_id, role.name, auth_user.user_id);
    Ok(Json(CreateRoleResponse {
        role_id: role.role_id,
        name: role.name,
        description: role.description,
        created_at: role.created_at,
    }))
}

// Endpoint: PATCH /api/v1/roles/:role_id - Update a role
#[derive(Deserialize)]
struct UpdateRoleRequest {
    name: Option<String>,
    description: Option<String>,
    permissions: Option<Vec<String>>, // Optional update to permissions
}

#[derive(Serialize)]
struct UpdateRoleResponse {
    role_id: i32,
    name: String,
    description: Option<String>,
    updated_at: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id))]
pub async fn update_role(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path(role_id): Path<i32>,
    Json(request): Json<UpdateRoleRequest>,
) -> Result<Json<UpdateRoleResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Updating role role_id: {} by user_id: {}", role_id, auth_user.user_id);
    tracing::Span::current().record("user_id", &auth_user.user_id);

    // Check if user has platform-wide update permission
    let has_permission = sqlx::query_scalar!(
        r#"
        SELECT 1
        FROM permissions p
        JOIN users u ON u.role_id = p.role_id
        WHERE u.user_id = $1 AND p.api_endpoint = '/api/v1/roles' AND p.permission_type = 'update'
        "#,
        auth_user.user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking permissions: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if !has_permission {
        error!("User {} lacks update permission for /api/v1/roles", auth_user.user_id);
        return Err((StatusCode::FORBIDDEN, "User lacks update permission".to_string()));
    }

    // Validate request data (if provided)
    if let Some(ref name) = request.name {
        if name.trim().is_empty() {
            error!("Role name cannot be empty");
            return Err((StatusCode::BAD_REQUEST, "Role name cannot be empty".to_string()));
        }
    }

    // Check if role exists
    let role_exists = sqlx::query!(
        "SELECT 1 FROM roles WHERE role_id = $1",
        role_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking role: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if !role_exists {
        error!("Role role_id: {} not found", role_id);
        return Err((StatusCode::NOT_FOUND, "Role not found".to_string()));
    }

    // Check for duplicate role name (if name is being updated)
    if let Some(ref name) = request.name {
        let name_exists = sqlx::query_scalar!(
            "SELECT 1 FROM roles WHERE name = $1 AND role_id != $2",
            name,
            role_id
        )
        .fetch_optional(&pool)
        .await
        .map_err(|e| { error!("Database error checking role name: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
        .is_some();

        if name_exists {
            error!("Role name '{}' already exists", name);
            return Err((StatusCode::CONFLICT, format!("Role name '{}' already exists", name)));
        }
    }

    // Validate permissions (if provided)
    if let Some(ref permissions) = request.permissions {
        for perm in permissions {
            let parts: Vec<&str> = perm.split(':').collect();
            if parts.len() != 2 || !["read", "create", "update", "delete"].contains(&parts[0]) || !parts[1].starts_with("/api/v1/") {
                error!("Invalid permission format: {}", perm);
                return Err((StatusCode::BAD_REQUEST, format!("Invalid permission format: '{}'. Use 'permission_type:api_endpoint'", perm)));
            }
        }
    }

    // Update role details
    let updated_role = sqlx::query_as!(
        UpdateRoleResponse,
        r#"
        UPDATE roles
        SET 
            name = COALESCE($1, name),
            description = COALESCE($2, description),
            updated_at = NOW()
        WHERE role_id = $3
        RETURNING role_id, name, description, updated_at
        "#,
        request.name,
        request.description,
        role_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error updating role: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    // Update permissions if provided
    if let Some(permissions) = request.permissions {
        // Delete existing permissions for this role
        sqlx::query!(
            "DELETE FROM permissions WHERE role_id = $1",
            role_id
        )
        .execute(&pool)
        .await
        .map_err(|e| { error!("Database error deleting old permissions: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

        // Insert new permissions
        for perm in permissions {
            let parts: Vec<&str> = perm.split(':').collect();
            sqlx::query!(
                r#"
                INSERT INTO permissions (role_id, permission_type, api_endpoint)
                VALUES ($1, $2, $3)
                "#,
                role_id,
                parts[0], // permission_type (e.g., "read")
                parts[1], // api_endpoint (e.g., "/api/v1/users")
            )
            .execute(&pool)
            .await
            .map_err(|e| { error!("Database error inserting permission: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;
        }
    }

    info!("Role updated: role_id={} by user_id: {}", role_id, auth_user.user_id);
    Ok(Json(updated_role))
}

// Endpoint: DELETE /api/v1/roles/:role_id - Delete a role
#[derive(Serialize)]
struct DeleteRoleResponse {
    message: String,
}

#[instrument(skip(pool), fields(user_id))]
pub async fn delete_role(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path(role_id): Path<i32>,
) -> Result<Json<DeleteRoleResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Deleting role role_id: {} by user_id: {}", role_id, auth_user.user_id);
    tracing::Span::current().record("user_id", &auth_user.user_id);

    // Check if user has platform-wide delete permission
    let has_permission = sqlx::query_scalar!(
        r#"
        SELECT 1
        FROM permissions p
        JOIN users u ON u.role_id = p.role_id
        WHERE u.user_id = $1 AND p.api_endpoint = '/api/v1/roles' AND p.permission_type = 'delete'
        "#,
        auth_user.user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking permissions: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if !has_permission {
        error!("User {} lacks delete permission for /api/v1/roles", auth_user.user_id);
        return Err((StatusCode::FORBIDDEN, "User lacks delete permission".to_string()));
    }

    // Check if role exists
    let role_exists = sqlx::query!(
        "SELECT 1 FROM roles WHERE role_id = $1",
        role_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking role: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if !role_exists {
        error!("Role role_id: {} not found", role_id);
        return Err((StatusCode::NOT_FOUND, "Role not found".to_string()));
    }

    // Check if role is in use by any users
    let role_in_use = sqlx::query_scalar!(
        "SELECT 1 FROM users WHERE role_id = $1",
        role_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking role usage: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if role_in_use {
        error!("Role role_id: {} is in use by users", role_id);
        return Err((StatusCode::BAD_REQUEST, "Role is in use by one or more users".to_string()));
    }

    // Delete associated permissions first (due to foreign key constraint)
    sqlx::query!(
        "DELETE FROM permissions WHERE role_id = $1",
        role_id
    )
    .execute(&pool)
    .await
    .map_err(|e| { error!("Database error deleting permissions: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    // Delete the role
    let result = sqlx::query!(
        "DELETE FROM roles WHERE role_id = $1 RETURNING role_id",
        role_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error deleting role: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    if result.is_none() {
        error!("Role role_id: {} not found during deletion", role_id);
        return Err((StatusCode::NOT_FOUND, "Role not found".to_string()));
    }

    info!("Role deleted: role_id={} by user_id: {}", role_id, auth_user.user_id);
    Ok(Json(DeleteRoleResponse {
        message: "Role deleted successfully".to_string(),
    }))
}
