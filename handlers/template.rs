// src/handlers/template.rs
// Template endpoint handlers for the ROSCA Platform API
// Provides sample JSON, CSV, and Excel files for ROSCA data import

use axum::{http::{StatusCode, HeaderValue}, extract::{State, Path, Query}, Json};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{debug, error, info, instrument};
use crate::handlers::auth::extract_auth_user;

// Authentication extractor
struct AuthUser { user_id: i32; }

// Endpoint: GET /api/v1/roscas/:rosca_id/templates - Download a template for ROSCA data import
#[derive(Deserialize)]
struct TemplateFilter {
    template_type: String, // "json", "csv", "excel"
    template: String, // "members", "contributions", "loans", "payouts", "settings", etc.
}

#[derive(Serialize)]
struct TemplateResponse {
    data: String, // Encoded template data (plain JSON/CSV string or base64 for Excel)
    format: String, // "json", "csv", or "excel"
}

#[instrument(skip(pool), fields(user_id))]
pub async fn get_template(
    auth_header: HeaderValue,
    State(pool): State<PgPool>,
    Path(rosca_id): Path<i32>,
    Query(filter): Query<TemplateFilter>,
) -> Result<Json<TemplateResponse>, (StatusCode, String)> {
    let auth_user = extract_auth_user(auth_header)
        .map_err(|e| { error!("Authentication failed: {}", e.1); e })?;

    info!("Fetching template for rosca_id: {} by user_id: {}", rosca_id, auth_user.user_id);
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

    // Validate template_type and template
    let template_type = filter.template_type.to_lowercase();
    let valid_types = vec!["json", "csv", "excel"];
    if !valid_types.contains(&template_type.as_str()) {
        error!("Invalid template type: {}", template_type);
        return Err((StatusCode::BAD_REQUEST, format!("Invalid template type. Supported: {:?}", valid_types)));
    }

    let template = filter.template.to_lowercase();
    let valid_templates = vec!["members", "contributions", "loans", "payouts", "settings"];
    if !valid_templates.contains(&template.as_str()) {
        error!("Invalid template: {}", template);
        return Err((StatusCode::BAD_REQUEST, format!("Invalid template. Supported: {:?}", valid_templates)));
    }

    // Fetch ROSCA details for context (contribution_amount for sample data)
    let rosca = sqlx::query!(
        r#"
        SELECT contribution_amount
        FROM roscas
        WHERE rosca_id = $1
        "#,
        rosca_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!("Database error fetching ROSCA: {}", e); (StatusCode::NOT_FOUND, "ROSCA not found".to_string()) })?;

    // Generate template based on type and template
    let template_data = match template.as_str() {
        "members" => match template_type.as_str() {
            "json" => serde_json::json!([
                {"user_id": 1, "member_type": "member", "status": "pending"}
            ]).to_string(),
            "csv" => "user_id,member_type,status\n1,member,pending\n".to_string(),
            "excel" => {
                let mut wb = xlsx::Workbook::new();
                let ws = wb.add_worksheet("Members");
                ws.write_string(0, 0, "user_id")?;
                ws.write_string(0, 1, "member_type")?;
                ws.write_string(0, 2, "status")?;
                ws.write_number(1, 0, 1.0)?;
                ws.write_string(1, 1, "member")?;
                ws.write_string(1, 2, "pending")?;
                let excel_data = wb.close()
                    .map_err(|e| { error!("Excel serialization error: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;
                base64::encode(&excel_data)
            },
            _ => unreachable!(),
        },
        "contributions" => {
            let sample_amount = rosca.contribution_amount.unwrap_or(100.0);
            match template_type.as_str() {
                "json" => serde_json::json!([
                    {"user_id": 1, "amount": sample_amount, "cycle_number": 1, "status": "pending", "paid_at": "2025-03-15T00:00:00Z"}
                ]).to_string(),
                "csv" => format!("user_id,amount,cycle_number,status,paid_at\n1,{},1,pending,2025-03-15T00:00:00Z\n", sample_amount),
                "excel" => {
                    let mut wb = xlsx::Workbook::new();
                    let ws = wb.add_worksheet("Contributions");
                    ws.write_string(0, 0, "user_id")?;
                    ws.write_string(0, 1, "amount")?;
                    ws.write_string(0, 2, "cycle_number")?;
                    ws.write_string(0, 3, "status")?;
                    ws.write_string(0, 4, "paid_at")?;
                    ws.write_number(1, 0, 1.0)?;
                    ws.write_number(1, 1, sample_amount)?;
                    ws.write_number(1, 2, 1.0)?;
                    ws.write_string(1, 3, "pending")?;
                    ws.write_string(1, 4, "2025-03-15T00:00:00Z")?;
                    let excel_data = wb.close()
                        .map_err(|e| { error!("Excel serialization error: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;
                    base64::encode(&excel_data)
                },
                _ => unreachable!(),
            }
        },
        "loans" => match template_type.as_str() {
            "json" => serde_json::json!([
                {"user_id": 1, "amount": 500.0, "interest_rate": 5.0, "status": "pending", "disbursement_status": "pending"}
            ]).to_string(),
            "csv" => "user_id,amount,interest_rate,status,disbursement_status\n1,500.0,5.0,pending,pending\n".to_string(),
            "excel" => {
                let mut wb = xlsx::Workbook::new();
                let ws = wb.add_worksheet("Loans");
                ws.write_string(0, 0, "user_id")?;
                ws.write_string(0, 1, "amount")?;
                ws.write_string(0, 2, "interest_rate")?;
                ws.write_string(0, 3, "status")?;
                ws.write_string(0, 4, "disbursement_status")?;
                ws.write_number(1, 0, 1.0)?;
                ws.write_number(1, 1, 500.0)?;
                ws.write_number(1, 2, 5.0)?;
                ws.write_string(1, 3, "pending")?;
                ws.write_string(1, 4, "pending")?;
                let excel_data = wb.close()
                    .map_err(|e| { error!("Excel serialization error: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;
                base64::encode(&excel_data)
            },
            _ => unreachable!(),
        },
        "payouts" => match template_type.as_str() {
            "json" => serde_json::json!([
                {"user_id": 1, "amount": 1000.0, "cycle_number": 1, "payout_status": "pending"}
            ]).to_string(),
            "csv" => "user_id,amount,cycle_number,payout_status\n1,1000.0,1,pending\n".to_string(),
            "excel" => {
                let mut wb = xlsx::Workbook::new();
                let ws = wb.add_worksheet("Payouts");
                ws.write_string(0, 0, "user_id")?;
                ws.write_string(0, 1, "amount")?;
                ws.write_string(0, 2, "cycle_number")?;
                ws.write_string(0, 3, "payout_status")?;
                ws.write_number(1, 0, 1.0)?;
                ws.write_number(1, 1, 1000.0)?;
                ws.write_number(1, 2, 1.0)?;
                ws.write_string(1, 3, "pending")?;
                let excel_data = wb.close()
                    .map_err(|e| { error!("Excel serialization error: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;
                base64::encode(&excel_data)
            },
            _ => unreachable!(),
        },
        "settings" => match template_type.as_str() {
            "json" => serde_json::json!({
                "cycle_type": "monthly",
                "cycle_length": 30,
                "contribution_amount": rosca.contribution_amount.unwrap_or(100.0),
                "payout_rules": {"payout_cycle": 3},
                "membership_rules_prefs": {"require_approval": true}
            }).to_string(),
            "csv" => format!(
                "cycle_type,cycle_length,contribution_amount,payout_cycle,require_approval\nmonthly,30,{},3,true\n",
                rosca.contribution_amount.unwrap_or(100.0)
            ),
            "excel" => {
                let mut wb = xlsx::Workbook::new();
                let ws = wb.add_worksheet("Settings");
                ws.write_string(0, 0, "cycle_type")?;
                ws.write_string(0, 1, "cycle_length")?;
                ws.write_string(0, 2, "contribution_amount")?;
                ws.write_string(0, 3, "payout_cycle")?;
                ws.write_string(0, 4, "require_approval")?;
                ws.write_string(1, 0, "monthly")?;
                ws.write_number(1, 1, 30.0)?;
                ws.write_number(1, 2, rosca.contribution_amount.unwrap_or(100.0))?;
                ws.write_number(1, 3, 3.0)?;
                ws.write_string(1, 4, "true")?;
                let excel_data = wb.close()
                    .map_err(|e| { error!("Excel serialization error: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()) })?;
                base64::encode(&excel_data)
            },
            _ => unreachable!(),
        },
        _ => unreachable!(),
    };

    info!(
        "Generated {} template for {} in rosca_id: {} by user_id: {}",
        template_type, template, rosca_id, auth_user.user_id
    );
    Ok(Json(TemplateResponse {
        data: template_data,
        format: template_type,
    }))
}
