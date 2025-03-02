// src/handlers/partner.rs
// Partner endpoint handlers for the ROSCA Platform API

use axum::{http::{StatusCode, HeaderValue}, extract::{State, Path, Query}, Json};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{debug, error, info, instrument};
use chrono::{DateTime, Utc};
use crate::handlers::auth::extract_auth_user;

// Authentication extractor
struct AuthUser { user_id: i32; }

// Endpoint 21: GET /api/v1/roscas/:rosca_id/partners - List linked partners
#[derive(Deserialize)]
struct PartnerFilter {
    status: Option<String>,
    limit: Option<i32>,
    offset: Option<i32>,
}

#[derive(Serialize, sqlx::FromRow)]
struct LinkedPartner {
    partner_id: i32,
    rosca_id: i32,
    name: String,
    status: String,
    created_at: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
pub async fn list_partners(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path(rosca_id): Path<i32>,
    Query(filter): Query<PartnerFilter>,
) -> Result<Json<Vec<LinkedPartner>>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Listing linked partners for rosca_id: {} by user_id: {}", rosca_id, auth_user.user_id);
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

    // Apply filters for linked partners
    let limit = filter.limit.unwrap_or(50).max(1).min(100);
    let offset = filter.offset.unwrap_or(0).max(0);
    let mut conditions = vec!["rpl.rosca_id = $1"];
    let mut params: Vec<&(dyn sqlx::Encode<'_, sqlx::Postgres> + sqlx::Type<sqlx::Postgres> + Sync)> = vec![&rosca_id];
    let mut param_index = 2;

    if let Some(ref status) = filter.status {
        conditions.push(format!("rpl.status = ${}", param_index));
        params.push(status);
        param_index += 1;
    }

    // Fetch linked partners with pagination
    let query = format!(
        r#"
        SELECT 
            rpl.partner_id,
            rpl.rosca_id,
            rp.name,
            rpl.status,
            rpl.created_at
        FROM rosca_partner_links rpl
        JOIN rosca_partners rp ON rpl.partner_id = rp.partner_id
        {}
        ORDER BY rpl.created_at DESC
        LIMIT ${} OFFSET ${}
        "#,
        if conditions.is_empty() { "WHERE rpl.rosca_id = $1" } else { format!("WHERE {}", conditions.join(" AND ")) },
        param_index,
        param_index + 1
    );
    params.push(&limit);
    params.push(&offset);

    let partners = sqlx::query_as_with::<_, LinkedPartner, _>(&query, params)
        .fetch_all(&pool)
        .await
        .map_err(|e| { error!("Database error fetching linked partners: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    info!("Retrieved {} linked partners for rosca_id: {}", partners.len(), rosca_id);
    Ok(Json(partners))
}

// Endpoint 22: POST /api/v1/roscas/:rosca_id/partners - Link a partner
#[derive(Deserialize)]
struct LinkPartnerRequest {
    partner_id: i32,
}

#[derive(Serialize)]
struct LinkPartnerResponse {
    partner_id: i32,
    rosca_id: i32,
    status: String,
    created_at: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
pub async fn link_partner(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path(rosca_id): Path<i32>,
    Json(request): Json<LinkPartnerRequest>,
) -> Result<Json<LinkPartnerResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Linking partner for rosca_id: {} by user_id: {}", rosca_id, auth_user.user_id);
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

    // Check if the partner exists
    let partner_exists = sqlx::query!(
        "SELECT 1 FROM rosca_partners WHERE partner_id = $1",
        request.partner_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking partner: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if !partner_exists {
        error!("Partner partner_id: {} not found", request.partner_id);
        return Err((StatusCode::NOT_FOUND, "Partner not found".to_string()));
    }

    // Check if the partner is already linked to the ROSCA
    let already_linked = sqlx::query!(
        "SELECT 1 FROM rosca_partner_links WHERE rosca_id = $1 AND partner_id = $2",
        rosca_id,
        request.partner_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking existing link: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if already_linked {
        error!("Partner partner_id: {} is already linked to rosca_id: {}", request.partner_id, rosca_id);
        return Err((StatusCode::CONFLICT, "Partner is already linked to this ROSCA".to_string()));
    }

    // Create the partner link
    let link = sqlx::query_as!(
        LinkPartnerResponse,
        r#"
        INSERT INTO rosca_partner_links (rosca_id, partner_id, status)
        VALUES ($1, $2, 'active')
        RETURNING partner_id, rosca_id, status, created_at
        "#,
        rosca_id,
        request.partner_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error linking partner: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    info!("Partner linked: partner_id={} to rosca_id={} with status={}", request.partner_id, rosca_id, link.status);
    Ok(Json(link))
}

// Endpoint 23: PATCH /api/v1/roscas/:rosca_id/partners/:partner_id/status - Update partner link status
#[derive(Deserialize)]
struct UpdatePartnerStatusRequest {
    status: String,
}

#[derive(Serialize)]
struct UpdatePartnerStatusResponse {
    partner_id: i32,
    rosca_id: i32,
    status: String,
    updated_at: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
pub async fn update_partner_status(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path((rosca_id, partner_id)): Path<(i32, i32)>,
    Json(request): Json<UpdatePartnerStatusRequest>,
) -> Result<Json<UpdatePartnerStatusResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Updating partner status for partner_id: {} in rosca_id: {} by user_id: {}", partner_id, rosca_id, auth_user.user_id);
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
    let valid_statuses = vec!["active", "inactive"];
    if !valid_statuses.contains(&request.status.as_str()) {
        error!("Invalid partner link status: {}", request.status);
        return Err((StatusCode::BAD_REQUEST, "Invalid partner link status".to_string()));
    }

    // Check if the partner link exists
    let link_exists = sqlx::query!(
        "SELECT 1 FROM rosca_partner_links WHERE rosca_id = $1 AND partner_id = $2",
        rosca_id,
        partner_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking partner link: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if !link_exists {
        error!("Partner link for partner_id: {} not found in rosca_id: {}", partner_id, rosca_id);
        return Err((StatusCode::NOT_FOUND, "Partner link not found in this ROSCA".to_string()));
    }

    // Update partner link status
    let link = sqlx::query_as!(
        UpdatePartnerStatusResponse,
        r#"
        UPDATE rosca_partner_links
        SET 
            status = $1,
            updated_at = NOW()
        WHERE rosca_id = $2 AND partner_id = $3
        RETURNING partner_id, rosca_id, status, updated_at
        "#,
        request.status,
        rosca_id,
        partner_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error updating partner link status: {}", e); (StatusCode::NOT_FOUND, "Partner link not found".to_string()) })?;

    info!("Partner link status updated: partner_id={} in rosca_id={} to status={}", partner_id, rosca_id, link.status);
    Ok(Json(link))
}

// Endpoint 34: GET /api/v1/rosca_partners - List all partners
#[derive(Deserialize)]
struct RoscaPartnerFilter {
    limit: Option<i32>,
    offset: Option<i32>,
}

#[derive(Serialize, sqlx::FromRow)]
struct RoscaPartner {
    partner_id: i32,
    name: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id))]
pub async fn list_rosca_partners(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Query(filter): Query<RoscaPartnerFilter>,
) -> Result<Json<Vec<RoscaPartner>>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Listing all ROSCA partners by user_id: {}", auth_user.user_id);
    tracing::Span::current().record("user_id", &auth_user.user_id);

    // Check if user has platform-wide read permission
    let has_permission = sqlx::query_scalar!(
        r#"
        SELECT 1
        FROM permissions p
        JOIN users u ON u.role_id = p.role_id
        WHERE u.user_id = $1 AND p.api_endpoint = '/api/v1/rosca_partners' AND p.permission_type = 'read'
        "#,
        auth_user.user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking permissions: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if !has_permission {
        error!("User {} lacks read permission for /api/v1/rosca_partners", auth_user.user_id);
        return Err((StatusCode::FORBIDDEN, "User lacks read permission".to_string()));
    }

    // Apply filters for partners
    let limit = filter.limit.unwrap_or(50).max(1).min(100);
    let offset = filter.offset.unwrap_or(0).max(0);

    // Fetch all partners with pagination
    let partners = sqlx::query_as!(
        RoscaPartner,
        r#"
        SELECT 
            partner_id,
            name,
            created_at,
            updated_at
        FROM rosca_partners
        ORDER BY created_at DESC
        LIMIT $1 OFFSET $2
        "#,
        limit as i64,
        offset as i64
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| { error!("Database error fetching partners: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    info!("Retrieved {} ROSCA partners for user_id: {}", partners.len(), auth_user.user_id);
    Ok(Json(partners))
}

// Endpoint 35: POST /api/v1/rosca_partners - Create a partner
#[derive(Deserialize)]
struct CreateRoscaPartnerRequest {
    name: String,
}

#[derive(Serialize)]
struct CreateRoscaPartnerResponse {
    partner_id: i32,
    name: String,
    created_at: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id))]
pub async fn create_rosca_partner(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Json(request): Json<CreateRoscaPartnerRequest>,
) -> Result<Json<CreateRoscaPartnerResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Creating ROSCA partner by user_id: {}", auth_user.user_id);
    tracing::Span::current().record("user_id", &auth_user.user_id);

    // Check if user has platform-wide create permission
    let has_permission = sqlx::query_scalar!(
        r#"
        SELECT 1
        FROM permissions p
        JOIN users u ON u.role_id = p.role_id
        WHERE u.user_id = $1 AND p.api_endpoint = '/api/v1/rosca_partners' AND p.permission_type = 'create'
        "#,
        auth_user.user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking permissions: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if !has_permission {
        error!("User {} lacks create permission for /api/v1/rosca_partners", auth_user.user_id);
        return Err((StatusCode::FORBIDDEN, "User lacks create permission".to_string()));
    }

    // Validate request data
    if request.name.trim().is_empty() {
        error!("Invalid partner name: cannot be empty");
        return Err((StatusCode::BAD_REQUEST, "Partner name cannot be empty".to_string()));
    }

    // Check if a partner with the same name already exists
    let name_exists = sqlx::query_scalar!(
        "SELECT 1 FROM rosca_partners WHERE name = $1",
        request.name
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking partner name: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if name_exists {
        error!("Partner name '{}' already exists", request.name);
        return Err((StatusCode::CONFLICT, format!("Partner name '{}' already exists", request.name)));
    }

    // Create the partner
    let partner = sqlx::query_as!(
        CreateRoscaPartnerResponse,
        r#"
        INSERT INTO rosca_partners (name)
        VALUES ($1)
        RETURNING partner_id, name, created_at
        "#,
        request.name
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error creating partner: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    info!("ROSCA partner created: partner_id={} with name='{}' by user_id: {}", partner.partner_id, partner.name, auth_user.user_id);
    Ok(Json(partner))
}

// Endpoint 77: DELETE /api/v1/roscas/:rosca_id/partners/:partner_id - Remove partner link
#[derive(Serialize)]
struct DeletePartnerLinkResponse {
    partner_id: i32,
    rosca_id: i32,
    message: String,
}

#[instrument(skip(pool), fields(user_id, rosca_id))]
pub async fn delete_partner_link(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path((rosca_id, partner_id)): Path<(i32, i32)>,
) -> Result<Json<DeletePartnerLinkResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Deleting partner link for partner_id: {} from rosca_id: {} by user_id: {}", partner_id, rosca_id, auth_user.user_id);
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

    // Check if the partner link exists
    let link_exists = sqlx::query!(
        "SELECT 1 FROM rosca_partner_links WHERE rosca_id = $1 AND partner_id = $2",
        rosca_id,
        partner_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking partner link: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if !link_exists {
        error!("Partner link for partner_id: {} not found in rosca_id: {}", partner_id, rosca_id);
        return Err((StatusCode::NOT_FOUND, "Partner link not found in this ROSCA".to_string()));
    }

    // Delete the partner link
    let result = sqlx::query!(
        "DELETE FROM rosca_partner_links WHERE rosca_id = $1 AND partner_id = $2 RETURNING partner_id",
        rosca_id,
        partner_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error deleting partner link: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;

    if result.is_none() {
        error!("Partner link for partner_id: {} not found in rosca_id: {}", partner_id, rosca_id);
        return Err((StatusCode::NOT_FOUND, "Partner link not found".to_string()));
    }

    info!("Partner link deleted: partner_id={} from rosca_id={}", partner_id, rosca_id);
    Ok(Json(DeletePartnerLinkResponse {
        partner_id,
        rosca_id,
        message: "Partner link removed successfully".to_string(),
    }))
}

// Endpoint 84: PATCH /api/v1/rosca_partners/:partner_id - Update partner details
#[derive(Deserialize)]
struct UpdateRoscaPartnerRequest {
    name: Option<String>,
}

#[derive(Serialize)]
struct UpdateRoscaPartnerResponse {
    partner_id: i32,
    name: String,
    updated_at: DateTime<Utc>,
}

#[instrument(skip(pool), fields(user_id))]
pub async fn update_rosca_partner(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path(partner_id): Path<i32>,
    Json(request): Json<UpdateRoscaPartnerRequest>,
) -> Result<Json<UpdateRoscaPartnerResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Updating ROSCA partner partner_id: {} by user_id: {}", partner_id, auth_user.user_id);
    tracing::Span::current().record("user_id", &auth_user.user_id);

    // Check if user has platform-wide update permission
    let has_permission = sqlx::query_scalar!(
        r#"
        SELECT 1
        FROM permissions p
        JOIN users u ON u.role_id = p.role_id
        WHERE u.user_id = $1 AND p.api_endpoint = '/api/v1/rosca_partners' AND p.permission_type = 'update'
        "#,
        auth_user.user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking permissions: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if !has_permission {
        error!("User {} lacks update permission for /api/v1/rosca_partners", auth_user.user_id);
        return Err((StatusCode::FORBIDDEN, "User lacks update permission".to_string()));
    }

    // Validate request data (if provided)
    if let Some(ref name) = request.name {
        if name.trim().is_empty() {
            error!("Invalid partner name: cannot be empty");
            return Err((StatusCode::BAD_REQUEST, "Partner name cannot be empty".to_string()));
        }
    }

    // Check if the partner exists
    let partner_exists = sqlx::query!(
        "SELECT 1 FROM rosca_partners WHERE partner_id = $1",
        partner_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!("Database error checking partner: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
    .is_some();

    if !partner_exists {
        error!("Partner partner_id: {} not found", partner_id);
        return Err((StatusCode::NOT_FOUND, "Partner not found".to_string()));
    }

    // If name is provided, check for duplicates excluding the current partner
    if let Some(ref name) = request.name {
        let name_taken = sqlx::query_scalar!(
            "SELECT 1 FROM rosca_partners WHERE name = $1 AND partner_id != $2",
            name,
            partner_id
        )
        .fetch_optional(&pool)
        .await
        .map_err(|e| { error!("Database error checking partner name: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?
        .is_some();

        if name_taken {
            error!("Partner name '{}' is already in use by another partner", name);
            return Err((StatusCode::CONFLICT, format!("Partner name '{}' is already in use", name)));
        }
    }

    // Update the partner
    let partner = sqlx::query_as!(
        UpdateRoscaPartnerResponse,
        r#"
        UPDATE rosca_partners
        SET 
            name = COALESCE($1, name),
            updated_at = NOW()
        WHERE partner_id = $2
        RETURNING partner_id, name, updated_at
        "#,
        request.name,
        partner_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error updating partner: {}", e); (StatusCode::NOT_FOUND, "Partner not found".to_string()) })?;

    info!("ROSCA partner updated: partner_id={} with name='{}' by user_id: {}", partner.partner_id, partner.name, auth_user.user_id);
    Ok(Json(partner))
}
