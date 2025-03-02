CREATE TABLE users (
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    phone VARCHAR(20) NOT NULL UNIQUE,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    phone_verified BOOLEAN NOT NULL DEFAULT FALSE,
    role_id INTEGER NOT NULL REFERENCES roles(role_id) ON DELETE RESTRICT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_phone ON users(phone_number);
CREATE INDEX idx_users_role_id ON users(role_id);

CREATE TABLE roles (
    role_id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    description TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_roles_name ON roles(name);
CREATE INDEX idx_roles_is_active ON roles(is_active);

CREATE TABLE roscas (
    rosca_id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    contribution_amount NUMERIC(15, 2),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_roscas_name ON roscas(name);

CREATE TABLE rosca_settings (
    rosca_id INTEGER PRIMARY KEY REFERENCES roscas(rosca_id) ON DELETE CASCADE,
    cycle_type VARCHAR(20) NOT NULL CHECK (cycle_type IN ('daily', 'monthly', 'yearly')),
    cycle_length INTEGER NOT NULL CHECK (cycle_length BETWEEN 1 AND 365),
    contribution_amount NUMERIC(15, 2),
    payout_rules JSONB NOT NULL DEFAULT '{}',
    membership_rules_prefs JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_rosca_settings_cycle_type ON rosca_settings(cycle_type);

CREATE TABLE rosca_members (
    rosca_id INTEGER NOT NULL REFERENCES roscas(rosca_id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    member_type VARCHAR(20) NOT NULL CHECK (member_type IN ('admin', 'member')),
    status VARCHAR(20) NOT NULL CHECK (status IN ('pending', 'active', 'inactive')),
    joined_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    PRIMARY KEY (rosca_id, user_id)
);

CREATE INDEX idx_rosca_members_user_id ON rosca_members(user_id);
CREATE INDEX idx_rosca_members_status ON rosca_members(status);


CREATE TABLE contributions (
    contribution_id SERIAL PRIMARY KEY,
    rosca_id INTEGER NOT NULL REFERENCES roscas(rosca_id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    amount NUMERIC(15, 2) NOT NULL CHECK (amount > 0),
    cycle_number INTEGER NOT NULL CHECK (cycle_number >= 1),
    status VARCHAR(20) NOT NULL CHECK (status IN ('pending', 'completed', 'rejected')),
    paid_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_contributions_rosca_id ON contributions(rosca_id);
CREATE INDEX idx_contributions_user_id ON contributions(user_id);
CREATE INDEX idx_contributions_status ON contributions(status);


CREATE TABLE loans (
    loan_id SERIAL PRIMARY KEY,
    rosca_id INTEGER NOT NULL REFERENCES roscas(rosca_id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    amount NUMERIC(15, 2) NOT NULL CHECK (amount > 0),
    interest_rate NUMERIC(5, 2) NOT NULL CHECK (interest_rate >= 0),
    repayment_cycles INTEGER NOT NULL CHECK (repayment_cycles >= 1),
    status VARCHAR(20) NOT NULL CHECK (status IN ('pending', 'active', 'repaid', 'defaulted')),
    disbursement_status VARCHAR(20) NOT NULL CHECK (disbursement_status IN ('pending', 'completed')),
    disbursed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_loans_rosca_id ON loans(rosca_id);
CREATE INDEX idx_loans_user_id ON loans(user_id);
CREATE INDEX idx_loans_status ON loans(status);

CREATE TABLE payouts (
    payout_id SERIAL PRIMARY KEY,
    rosca_id INTEGER NOT NULL REFERENCES roscas(rosca_id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    amount NUMERIC(15, 2) NOT NULL CHECK (amount > 0),
    cycle_number INTEGER NOT NULL CHECK (cycle_number >= 1),
    payout_status VARCHAR(20) NOT NULL CHECK (payout_status IN ('pending', 'completed')),
    payout_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_payouts_rosca_id ON payouts(rosca_id);
CREATE INDEX idx_payouts_user_id ON payouts(user_id);
CREATE INDEX idx_payouts_payout_status ON payouts(payout_status);

CREATE TABLE penalties (
    penalty_id SERIAL PRIMARY KEY,
    rosca_id INTEGER NOT NULL REFERENCES roscas(rosca_id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    amount NUMERIC(15, 2) NOT NULL CHECK (amount > 0),
    reason TEXT NOT NULL,
    status VARCHAR(20) NOT NULL CHECK (status IN ('pending', 'paid', 'waived')),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_penalties_rosca_id ON penalties(rosca_id);
CREATE INDEX idx_penalties_user_id ON penalties(user_id);
CREATE INDEX idx_penalties_status ON penalties(status);


CREATE TABLE repayments (
    repayment_id SERIAL PRIMARY KEY,
    loan_id INTEGER NOT NULL REFERENCES loans(loan_id) ON DELETE CASCADE,
    amount NUMERIC(15, 2) NOT NULL CHECK (amount > 0),
    cycle_number INTEGER NOT NULL CHECK (cycle_number >= 1),
    status VARCHAR(20) NOT NULL CHECK (status IN ('pending', 'completed')),
    paid_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_repayments_loan_id ON repayments(loan_id);
CREATE INDEX idx_repayments_status ON repayments(status);


CREATE TABLE rosca_partners (
    partner_id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    status VARCHAR(20) NOT NULL CHECK (status IN ('pending', 'active', 'inactive')),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_rosca_partners_name ON rosca_partners(name);
CREATE INDEX idx_rosca_partners_status ON rosca_partners(status);

CREATE TABLE rosca_partner_links (
    rosca_id INTEGER NOT NULL REFERENCES roscas(rosca_id) ON DELETE CASCADE,
    partner_id INTEGER NOT NULL REFERENCES rosca_partners(partner_id) ON DELETE CASCADE,
    status VARCHAR(20) NOT NULL CHECK (status IN ('pending', 'active', 'inactive')),
    linked_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    PRIMARY KEY (rosca_id, partner_id)
);

CREATE INDEX idx_rosca_partner_links_partner_id ON rosca_partner_links(partner_id);
CREATE INDEX idx_rosca_partner_links_status ON rosca_partner_links(status);


CREATE TABLE notifications (
    notification_id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    notification_type VARCHAR(50) NOT NULL,
    message TEXT NOT NULL,
    status VARCHAR(20) NOT NULL CHECK (status IN ('pending', 'completed', 'failed')),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    sent_at TIMESTAMP WITH TIME ZONE,
    read_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_notifications_user_id ON notifications(user_id);
CREATE INDEX idx_notifications_status ON notifications(status);


CREATE TABLE verification_codes (
    user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    code_type VARCHAR(20) NOT NULL CHECK (code_type IN ('email', 'phone', 'password_reset')),
    code VARCHAR(6) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, code_type)
);

CREATE INDEX idx_verification_codes_expires_at ON verification_codes(expires_at);







