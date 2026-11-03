# Vault console loader implementation plan
> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.
**Goal:** Vault-managed console Clerk credentials and one-token Club API bootstrap.
**Architecture:** Existing SDK live app transport, finite shared-only vault-app contract, private bootstrap identities, dynamic Clerk request handoff. Operator proxy authority remains independent.
**Tech Stack:** TypeScript, Next.js, NestJS, Clerk, existing runtime-client.
**Spec:** docs/superpowers/specs/2026-11-03-vault-console-loader-design.md

- [x] Tests first: console contract/tenant denial and live loader adoption/failclosed/legacy behavior.
- [x] Implement contract and console loader, lazy Clerk imports and middleware handling.
- [x] Typecheck, relevant tests, frontend build and fresh review.
- [x] Backup ENV, provision own app references/token without changing existing manifests, preserve Clerk bytes and enable narrow Club provider capability.
- [x] Verify actual runtime reads/refresh and identity isolation; patch versions, commit/push code only, keep private files ignored.

Verified: API232 tests/32suites, frontend127 tests, both typechecks/builds. Fresh review P1 stale-warning handling fixed with regression; finalreview no important findings. Running UIroot307/signin200; renderedHTML excludes secret/encryptionkey/bootstrap token. Actual own-loader read/refresh and genericwrite/tenant denials verified. Clubprovider capability authorized on1existing tenant, genericwrite stilldenied. Existingbusiness manifests verified unchanged. Privatebackups/ENV600 andignored; no services manuallyrestarted.
