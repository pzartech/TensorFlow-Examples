-- Tamper-evident audit log for Didit identity verifications.
-- Threat model: Case B — prove to a third party (regulator/auditor/court) that
-- the records were not altered after the fact, *including by the operator itself*.
-- Strategy: hash-chain every record, then anchor Merkle roots to a public blockchain.

-- One row per auditable event, hash-chained to the previous row.
create table if not exists audit_log (
  seq              bigint      primary key,        -- monotonic, gap-free order (from sequence below)
  event_type       text        not null,           -- e.g. 'didit.approved'
  subject_ref      text,                            -- pseudonymous ICI user id — NOT PII
  didit_session_id text,
  payload_hash     bytea       not null,            -- sha256 of canonical(payload)
  payload          jsonb       not null,            -- full event (internal only; may contain PII; never anchored)
  prev_hash        bytea       not null,            -- record_hash of seq-1 (32 zero bytes for genesis)
  record_hash      bytea       not null,            -- sha256(seq‖event_type‖payload_hash‖prev_hash‖created_at)
  created_at       timestamptz not null
);

-- Dedicated sequence so appendAuditEvent() can reserve seq *before* insert,
-- making each row immutable from the moment it is created.
create sequence if not exists audit_log_seq_seq owned by audit_log.seq;

-- Each anchor pins a contiguous range of the log to a public-chain timestamp.
create table if not exists audit_anchor (
  id            bigserial   primary key,
  from_seq      bigint      not null,
  to_seq        bigint      not null,
  merkle_root   bytea       not null,              -- root over record_hash of [from_seq..to_seq]
  ots_proof     bytea,                              -- OpenTimestamps proof (Bitcoin-backed)
  bitcoin_block integer,                            -- filled once confirmed
  anchored_at   timestamptz not null default now()
);

-- Append-only enforcement. Run as the table owner, then grant the app a write-once role.
-- (Adjust 'ici_app' to ICI's actual application role.)
revoke update, delete, truncate on audit_log from public;
-- grant insert, select on audit_log to ici_app;
-- grant usage on sequence audit_log_seq_seq to ici_app;
