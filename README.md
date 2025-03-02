# ROSCA Platform API

The ROSCA (Rotating Savings and Credit Association) Platform API is a Rust-based RESTful API built with Axum, SQLx, and PostgreSQL. 
It provides a comprehensive system for managing ROSCAs, including user authentication, role-based access control, financial transactions (contributions, loans, payouts, penalties, repayments), partner integrations, and advanced user analytics.

## Table of Contents
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
- [Environment Variables](#environment-variables)
- [API Endpoints](#api-endpoints)
- [Usage Examples](#usage-examples)
- [Contributing](#contributing)
- [License](#license)

## Features
- User authentication with email/phone verification and password reset.
- Role-based access control for platform and ROSCA admins.
- ROSCA management (creation, settings, members).
- Financial operations (contributions, loans, payouts, penalties, repayments).
- Partner linking and management.
- User reports, analytics, forecasts, and simulations.
- Template downloads for data import (JSON, CSV, Excel).
- Configurable payment gateways (M-PESA, PayPal, Stripe), email, and SMS services.

## Prerequisites
- Rust 1.75+
- PostgreSQL 15+
- Environment variables configured.

## Setup

1. **Clone the Repository**:
   git clone <repository-url>
   cd rosca-platform-api
   
2. **Set Up PostgreSQL:**:
   CREATE DATABASE rosca_db;
   
3. **Install Dependencies and Run:**:
   cargo check
   cargo build


## Feature Requests & Customizations
   - bariimacharia@gmail.com 


## Contributing
   - Fork the repository.
   - Create a feature branch (git checkout -b feature/add-endpoint).
   - Commit changes (git commit -am "Add new endpoint").
   - Push to the branch (git push origin feature/add-endpoint).
   - Create a pull request.
   
## License
This project is licensed under the MIT License.

## Coming Soon:
 - Alpha release.
 - More features inclusding the mobile app and the web admin.
 - Hosted instance for playing around with.
   


