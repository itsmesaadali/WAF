-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "public";

-- CreateTable
CREATE TABLE "admin_users" (
    "id" SERIAL NOT NULL,
    "username" VARCHAR(64) NOT NULL,
    "password_hash" TEXT NOT NULL,
    "failed_attempts" INTEGER NOT NULL DEFAULT 0,
    "locked_until" TIMESTAMPTZ(6),
    "last_login_at" TIMESTAMPTZ(6),
    "token_version" INTEGER NOT NULL DEFAULT 0,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "admin_users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "request_logs" (
    "id" BIGSERIAL NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "client_ip" VARCHAR(64) NOT NULL,
    "method" VARCHAR(16) NOT NULL,
    "path" TEXT NOT NULL,
    "query" TEXT,
    "user_agent" TEXT,
    "status_code" INTEGER NOT NULL,
    "action" VARCHAR(16) NOT NULL,
    "reason" TEXT,
    "waf_ms" DOUBLE PRECISION NOT NULL,
    "upstream_ms" DOUBLE PRECISION,
    "anomaly_score" DOUBLE PRECISION,
    "is_anomaly" BOOLEAN NOT NULL DEFAULT false,
    "features" JSONB,
    "mode" VARCHAR(16) NOT NULL,
    "simulated" BOOLEAN NOT NULL DEFAULT false,
    "upstream" TEXT,

    CONSTRAINT "request_logs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "incidents" (
    "id" BIGSERIAL NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "client_ip" VARCHAR(64) NOT NULL,
    "method" VARCHAR(16) NOT NULL,
    "path" TEXT NOT NULL,
    "attack_type" VARCHAR(32) NOT NULL,
    "severity" VARCHAR(16) NOT NULL,
    "rule_id" VARCHAR(64),
    "rule_name" TEXT,
    "location" TEXT,
    "evidence" TEXT,
    "action_taken" VARCHAR(16) NOT NULL,
    "anomaly_score" DOUBLE PRECISION,
    "mode" VARCHAR(16) NOT NULL,
    "status" VARCHAR(16) NOT NULL DEFAULT 'open',
    "simulated" BOOLEAN NOT NULL DEFAULT false,

    CONSTRAINT "incidents_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ip_bans" (
    "id" SERIAL NOT NULL,
    "ip" VARCHAR(64) NOT NULL,
    "reason" TEXT NOT NULL,
    "source" VARCHAR(16) NOT NULL,
    "created_by" VARCHAR(64),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMPTZ(6),
    "lifted_at" TIMESTAMPTZ(6),
    "lifted_by" VARCHAR(64),
    "simulated" BOOLEAN NOT NULL DEFAULT false,

    CONSTRAINT "ip_bans_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "audit_logs" (
    "id" BIGSERIAL NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "username" VARCHAR(64) NOT NULL,
    "action" VARCHAR(64) NOT NULL,
    "target" TEXT,
    "details" JSONB,
    "ip" VARCHAR(64),

    CONSTRAINT "audit_logs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "settings" (
    "key" VARCHAR(64) NOT NULL,
    "value" JSONB NOT NULL,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_by" VARCHAR(64),

    CONSTRAINT "settings_pkey" PRIMARY KEY ("key")
);

-- CreateTable
CREATE TABLE "ml_model_runs" (
    "id" SERIAL NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "source" VARCHAR(16) NOT NULL,
    "samples" INTEGER NOT NULL,
    "contamination" DOUBLE PRECISION NOT NULL,
    "threshold" DOUBLE PRECISION NOT NULL,
    "holdout_flag_rate" DOUBLE PRECISION NOT NULL,
    "feature_names" JSONB NOT NULL,
    "trained_by" VARCHAR(64),
    "active" BOOLEAN NOT NULL DEFAULT false,

    CONSTRAINT "ml_model_runs_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "admin_users_username_key" ON "admin_users"("username");

-- CreateIndex
CREATE INDEX "request_logs_created_at_idx" ON "request_logs"("created_at" DESC);

-- CreateIndex
CREATE INDEX "request_logs_client_ip_created_at_idx" ON "request_logs"("client_ip", "created_at" DESC);

-- CreateIndex
CREATE INDEX "request_logs_action_created_at_idx" ON "request_logs"("action", "created_at" DESC);

-- CreateIndex
CREATE INDEX "request_logs_is_anomaly_created_at_idx" ON "request_logs"("is_anomaly", "created_at" DESC);

-- CreateIndex
CREATE INDEX "incidents_created_at_idx" ON "incidents"("created_at" DESC);

-- CreateIndex
CREATE INDEX "incidents_attack_type_created_at_idx" ON "incidents"("attack_type", "created_at" DESC);

-- CreateIndex
CREATE INDEX "incidents_client_ip_created_at_idx" ON "incidents"("client_ip", "created_at" DESC);

-- CreateIndex
CREATE INDEX "incidents_status_created_at_idx" ON "incidents"("status", "created_at" DESC);

-- CreateIndex
CREATE INDEX "ip_bans_ip_idx" ON "ip_bans"("ip");

-- CreateIndex
CREATE INDEX "ip_bans_lifted_at_expires_at_idx" ON "ip_bans"("lifted_at", "expires_at");

-- CreateIndex
CREATE INDEX "audit_logs_created_at_idx" ON "audit_logs"("created_at" DESC);

-- CreateIndex
CREATE INDEX "ml_model_runs_created_at_idx" ON "ml_model_runs"("created_at" DESC);

