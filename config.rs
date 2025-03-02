// src/config.rs
// Configuration loading for the ROSCA Platform API

use std::env;
use serde::{Deserialize};

#[derive(Clone, Deserialize)]
pub struct AppConfig {
    pub env: String,
    pub port: u16,
    pub database_url: String,
    pub jwt_secret: String,
    pub email_smtp_host: String,
    pub email_smtp_port: u16,
    pub email_smtp_username: String,
    pub email_smtp_password: String,
    pub sms_api_key: String,
    pub sms_sender_id: String,
    pub mpesa_consumer_key: String,
    pub mpesa_consumer_secret: String,
    pub mpesa_shortcode: String,
    pub paypal_client_id: String,
    pub paypal_client_secret: String,
    pub paypal_base_url: String,
    pub stripe_api_key: String,
}

#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
    #[error("Missing or invalid environment variable: {0}")]
    EnvVar(String),
    #[error("Invalid port number: {0}")]
    InvalidPort(String),
}

impl AppConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let env = env::var("ENV").unwrap_or("dev".to_string()).to_lowercase();

        let port = env::var("PORT")
            .unwrap_or(match env.as_str() {
                "dev" => "3000".to_string(),
                "uat" => "3001".to_string(),
                "prod" => "8080".to_string(),
                _ => "3000".to_string(),
            })
            .parse::<u16>()
            .map_err(|e| ConfigError::InvalidPort(e.to_string()))?;

        let database_url = env::var("DATABASE_URL")
            .unwrap_or(match env.as_str() {
                "dev" => "postgres://user:password@localhost:5432/rosca_db".to_string(),
                "uat" => "postgres://user:password@uat-db:5432/rosca_db".to_string(),
                "prod" => "postgres://user:password@prod-db:5432/rosca_db".to_string(),
                _ => "postgres://user:password@localhost:5432/rosca_db".to_string(),
            });

        let jwt_secret = env::var("JWT_SECRET")
            .unwrap_or(match env.as_str() {
                "dev" => "dev_secret".to_string(),
                "uat" => "uat_secret".to_string(),
                "prod" => "prod_secret".to_string(),
                _ => "dev_secret".to_string(),
            });

        let email_smtp_host = env::var("EMAIL_SMTP_HOST")
            .unwrap_or(match env.as_str() {
                "dev" => "localhost".to_string(),
                "uat" => "smtp.uat.example.com".to_string(),
                "prod" => "smtp.prod.example.com".to_string(),
                _ => "localhost".to_string(),
            });
        let email_smtp_port = env::var("EMAIL_SMTP_PORT")
            .unwrap_or(match env.as_str() {
                "dev" => "1025".to_string(),
                "uat" => "587".to_string(),
                "prod" => "587".to_string(),
                _ => "1025".to_string(),
            })
            .parse::<u16>()
            .map_err(|e| ConfigError::InvalidPort(e.to_string()))?;
        let email_smtp_username = env::var("EMAIL_SMTP_USERNAME")
            .unwrap_or(match env.as_str() {
                "dev" => "".to_string(),
                "uat" => "uat_user".to_string(),
                "prod" => "prod_user".to_string(),
                _ => "".to_string(),
            });
        let email_smtp_password = env::var("EMAIL_SMTP_PASSWORD")
            .unwrap_or(match env.as_str() {
                "dev" => "".to_string(),
                "uat" => "uat_pass".to_string(),
                "prod" => "prod_pass".to_string(),
                _ => "".to_string(),
            });

        let sms_api_key = env::var("SMS_API_KEY")
            .unwrap_or(match env.as_str() {
                "dev" => "dev_sms_key".to_string(),
                "uat" => "uat_sms_key".to_string(),
                "prod" => "prod_sms_key".to_string(),
                _ => "dev_sms_key".to_string(),
            });
        let sms_sender_id = env::var("SMS_SENDER_ID")
            .unwrap_or(match env.as_str() {
                "dev" => "ROSCA_DEV".to_string(),
                "uat" => "ROSCA_UAT".to_string(),
                "prod" => "ROSCA".to_string(),
                _ => "ROSCA_DEV".to_string(),
            });

        let mpesa_consumer_key = env::var("MPESA_CONSUMER_KEY")
            .unwrap_or(match env.as_str() {
                "dev" => "dev_mpesa_key".to_string(),
                "uat" => "uat_mpesa_key".to_string(),
                "prod" => "prod_mpesa_key".to_string(),
                _ => "dev_mpesa_key".to_string(),
            });
        let mpesa_consumer_secret = env::var("MPESA_CONSUMER_SECRET")
            .unwrap_or(match env.as_str() {
                "dev" => "dev_mpesa_secret".to_string(),
                "uat" => "uat_mpesa_secret".to_string(),
                "prod" => "prod_mpesa_secret".to_string(),
                _ => "dev_mpesa_secret".to_string(),
            });
        let mpesa_shortcode = env::var("MPESA_SHORTCODE")
            .unwrap_or(match env.as_str() {
                "dev" => "123456".to_string(),
                "uat" => "654321".to_string(),
                "prod" => "789012".to_string(),
                _ => "123456".to_string(),
            });

        let paypal_client_id = env::var("PAYPAL_CLIENT_ID")
            .unwrap_or(match env.as_str() {
                "dev" => "dev_paypal_client_id".to_string(),
                "uat" => "uat_paypal_client_id".to_string(),
                "prod" => "prod_paypal_client_id".to_string(),
                _ => "dev_paypal_client_id".to_string(),
            });
        let paypal_client_secret = env::var("PAYPAL_CLIENT_SECRET")
            .unwrap_or(match env.as_str() {
                "dev" => "dev_paypal_secret".to_string(),
                "uat" => "uat_paypal_secret".to_string(),
                "prod" => "prod_paypal_secret".to_string(),
                _ => "dev_paypal_secret".to_string(),
            });
        let paypal_base_url = env::var("PAYPAL_BASE_URL")
            .unwrap_or(match env.as_str() {
                "dev" => "https://api.sandbox.paypal.com".to_string(),
                "uat" => "https://api.sandbox.paypal.com".to_string(),
                "prod" => "https://api.paypal.com".to_string(),
                _ => "https://api.sandbox.paypal.com".to_string(),
            });

        let stripe_api_key = env::var("STRIPE_API_KEY")
            .unwrap_or(match env.as_str() {
                "dev" => "sk_test_dev_stripe_key".to_string(),
                "uat" => "sk_test_uat_stripe_key".to_string(),
                "prod" => "sk_live_prod_stripe_key".to_string(),
                _ => "sk_test_dev_stripe_key".to_string(),
            });

        Ok(AppConfig {
            env,
            port,
            database_url,
            jwt_secret,
            email_smtp_host,
            email_smtp_port,
            email_smtp_username,
            email_smtp_password,
            sms_api_key,
            sms_sender_id,
            mpesa_consumer_key,
            mpesa_consumer_secret,
            mpesa_shortcode,
            paypal_client_id,
            paypal_client_secret,
            paypal_base_url,
            stripe_api_key,
        })
    }
}
