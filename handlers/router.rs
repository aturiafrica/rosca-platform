// src/handlers/router.rs
// Defines the Axum router for the ROSCA Platform API

use axum::{Router, routing::{get, post, patch, delete}};
use sqlx::PgPool;

use super::{
    auth,
    contribution,
    loan,
    member,
    partner,
    payout,
    penalty,
    repayment,
    role,
    rosca,
    settings,
    template,
    user,
};

#[derive(Clone)]
pub struct AppConfig {
    pub jwt_secret: String,
    pub email_smtp_host: String,
    pub email_smtp_port: u16,
    pub email_smtp_username: String,
    pub email_smtp_password: String,
    pub sms_api_key: String,
    pub sms_sender_id: String,
}

pub fn create_router(pool: PgPool) -> Router {
    Router::new()
        // Authentication Routes
        .route("/api/v1/auth/login", post(auth::login))
        .route("/api/v1/auth/logout", post(auth::logout))
        .route("/api/v1/auth/register", post(auth::register))
        .route("/api/v1/auth/email_verify", post(auth::email_verify))
        .route("/api/v1/auth/email_verify/confirm", post(auth::confirm_email_verify))
        .route("/api/v1/auth/phone_verify", post(auth::phone_verify))
        .route("/api/v1/auth/phone_verify/confirm", post(auth::confirm_phone_verify))
        .route("/api/v1/auth/password_reset", post(auth::password_reset))
        .route("/api/v1/auth/password_reset/verify", post(auth::verify_reset_code))

        // User Routes
        .route("/api/v1/users", get(user::list_users))
        .route("/api/v1/users/:user_id", patch(user::update_user))
        .route("/api/v1/users/:user_id", delete(user::delete_user))
        .route("/api/v1/users/me/reports", get(user::get_user_reports))
        .route("/api/v1/users/me/analytics", get(user::get_user_analytics))
        .route("/api/v1/users/me/notifications", get(user::get_user_notifications))
        .route("/api/v1/users/me/export", get(user::export_user_data))
        .route("/api/v1/users/me/forecast", get(user::get_user_forecast))
        .route("/api/v1/users/me/simulation", get(user::simulate_user_data))

        // Role Routes
        .route("/api/v1/roles", get(role::list_roles))
        .route("/api/v1/roles", post(role::create_role))
        .route("/api/v1/roles/:role_id", patch(role::update_role))
        .route("/api/v1/roles/:role_id", delete(role::delete_role))

        // Partner Routes
        .route("/api/v1/roscas/:rosca_id/partners", get(partner::list_partners))
        .route("/api/v1/roscas/:rosca_id/partners", post(partner::link_partner))
        .route("/api/v1/roscas/:rosca_id/partners/:partner_id/status", patch(partner::update_partner_status))
        .route("/api/v1/rosca_partners", get(partner::list_rosca_partners))
        .route("/api/v1/rosca_partners", post(partner::create_rosca_partner))
        .route("/api/v1/roscas/:rosca_id/partners/:partner_id", delete(partner::delete_partner_link))
        .route("/api/v1/rosca_partners/:partner_id", patch(partner::update_rosca_partner))

        // Contribution Routes
        .route("/api/v1/roscas/:rosca_id/contributions", get(contribution::list_contributions))
        .route("/api/v1/roscas/:rosca_id/contributions", post(contribution::create_contribution))
        .route("/api/v1/roscas/:rosca_id/contributions/:contribution_id/status", patch(contribution::update_contribution_status))

        // Repayment Routes
        .route("/api/v1/roscas/:rosca_id/loans/:loan_id/repayments", get(repayment::list_loan_repayments))
        .route("/api/v1/roscas/:rosca_id/loans/:loan_id/repayments", post(repayment::create_loan_repayment))
        .route("/api/v1/roscas/:rosca_id/loans/:loan_id/repayments/:repayment_id", patch(repayment::update_loan_repayment))

        // Penalty Routes
        .route("/api/v1/roscas/:rosca_id/penalties", get(penalty::list_penalties))
        .route("/api/v1/roscas/:rosca_id/penalties", post(penalty::create_penalty))
        .route("/api/v1/roscas/:rosca_id/penalties/:penalty_id/status", patch(penalty::update_penalty_status))

        // Template Routes
        .route("/api/v1/roscas/:rosca_id/templates", get(template::get_template))

        // Settings Routes
        .route("/api/v1/roscas/:rosca_id/settings", get(settings::get_settings))
        .route("/api/v1/roscas/:rosca_id/settings", patch(settings::update_settings))

        // Assumed ROSCA Routes
        .route("/api/v1/roscas", get(rosca::list_roscas))
        .route("/api/v1/roscas", post(rosca::create_rosca))
        .route("/api/v1/roscas/:rosca_id", patch(rosca::update_rosca))
        .route("/api/v1/roscas/:rosca_id", delete(rosca::delete_rosca))

        // Assumed Member Routes
        .route("/api/v1/roscas/:rosca_id/members", get(member::list_members))
        .route("/api/v1/roscas/:rosca_id/members", post(member::add_member))
        .route("/api/v1/roscas/:rosca_id/members/:user_id", delete(member::remove_member))

        // Assumed Payout Routes
        .route("/api/v1/roscas/:rosca_id/payouts", get(payout::list_payouts))
        .route("/api/v1/roscas/:rosca_id/payouts", post(payout::create_payout))
        .route("/api/v1/roscas/:rosca_id/payouts/:payout_id", patch(payout::update_payout))

        // Assumed Loan Routes
        .route("/api/v1/roscas/:rosca_id/loans", get(loan::list_loans))
        .route("/api/v1/roscas/:rosca_id/loans", post(loan::create_loan))
        .route("/api/v1/roscas/:rosca_id/loans/:loan_id", patch(loan::update_loan))

        // Pass the PgPool as state to all routes
        .with_state((pool, AppConfig {
            jwt_secret: String::new(),
            email_smtp_host: String::new(),
            email_smtp_port: 0,
            email_smtp_username: String::new(),
            email_smtp_password: String::new(),
            sms_api_key: String::new(),
            sms_sender_id: String::new(),
        }))
}
