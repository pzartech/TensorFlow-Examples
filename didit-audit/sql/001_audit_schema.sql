-- Tamper-evident audit log for Didit identity verifications.
-- Threat model: Case B — prove to a third party (regulator/auditor/court) that
-- the records were not altered after the fact, *including by the operator itself*.
-- Strategy: hash-chain every record, then anchor Merkle roots with as many
-- independent proofs as possible (Bitcoin, qualified RFC 3161 timestamps, EVM
-- chains, managed-key signatures). Redundancy = defence in depth.

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

-- Each anchor pins a contiguous range of the log to a Merkle root.
create table if not exists audit_anchor (
  id          bigserial   primary key,
  from_seq    bigint      not null,
  to_seq      bigint      not null,
  merkle_root bytea       not null,                -- root over record_hash of [from_seq..to_seq]
  anchored_at timestamptz not null default now()
);

-- Each anchor can carry MANY independent proofs of the same root. Add more
-- timestamp authorities / chains / keys and you simply get more rows here.
create table if not exists audit_anchor_proof (
  id            bigserial   primary key,
  anchor_id     bigint      not null references audit_anchor(id) on delete restrict,
  method        text        not null,              -- 'bitcoin-ots' | 'rfc3161' | 'evm' | 'signature'
  provider      text        not null,              -- instance id: TSA url, chain name, key id, ...
  proof         bytea       not null,              -- OTS proof | TST token | tx hash | signature
  asserted_time timestamptz,                        -- TSA genTime / block time, when available
  status        text        not null default 'pending', -- 'pending' | 'confirmed'
  detail        jsonb,
  created_at    timestamptz not null default now(),
  unique (anchor_id, method, provider)
);

-- Per-sink high-water mark for replicating full records to independent layers
-- (filesystem/WORM, S3 Object Lock, Azure immutable blob, ...).
create table if not exists audit_replication (
  sink       text        primary key,
  last_seq   bigint      not null default 0,
  updated_at timestamptz not null default now()
);

-- Append-only enforcement. Run as the table owner, then grant the app a
-- write-once role. (Adjust 'ici_app' to ICI's actual application role.)
revoke update, delete, truncate on audit_log from public;
-- grant insert, select on audit_log to ici_app;
-- grant usage on sequence audit_log_seq_seq to ici_app;
-- grant insert, select, update on audit_anchor, audit_anchor_proof to ici_app;
