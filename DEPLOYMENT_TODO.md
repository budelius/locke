# v0.10.0 deployment TODO

Python 0.10.0 is already published and needs no further action.

## Repository changes

- [x] Preserve the npm CLI metadata as an explicit executable mapping:
  `"bin": { "locke": "./dist/cli/main.js" }`.
- [x] Run `publish:npm` on the GitLab.com shared runner
  `saas-linux-small-amd64`. npm OIDC does not support the
  `obachan-staging-oss` project/self-hosted runner.
- [x] Allow `publish:crates` to recover from updated `main` when a pipeline is
  started with `PUBLISH_CRATES=1`.
- [ ] Commit these changes to !2 and merge !2 through `dev` into `main`.

Do not retry the existing v0.10.0 tag pipeline. It always checks out tag commit
`da4fd8c` and therefore uses that commit's old CI configuration.

## 1. First npm publication (manual login and 2FA)

The TypeScript dependencies must be installed before `npm run build`; otherwise
`tsc` is not available. From the repository root, run:

```bash
cd typescript
npm install --ignore-scripts --no-package-lock
npm run build
npm login
npm publish --access public
```

- [ ] Confirm the interactive publication of `@martin-wieser/locke@0.10.0`
  succeeds.

## 2. Configure npm Trusted Publishing

After the package exists on npm, configure its Trusted Publisher with:

- Namespace: `martin-wieser`
- Project: `locke`
- CI file: `.gitlab-ci.yml`
- Environment: `release`
- Allowed action: `npm publish`

- [ ] Save the npm Trusted Publisher configuration.

## 3. Configure crates.io Trusted Publishing

Configure Trusted Publishing for `locke-creds` with:

- Namespace: `martin-wieser`
- Project: `locke`
- CI/workflow file: `.gitlab-ci.yml`
- Environment: `release`

- [ ] Save the crates.io Trusted Publisher configuration before retrying OIDC.

## 4. Recover crates.io 0.10.0 from `main`

After the repository changes reach `main`, start a new pipeline for `main` with:

```text
PUBLISH_CRATES=1
```

This publishes the `0.10.0` version still present in `rust/Cargo.toml` without
moving or recreating the `v0.10.0` tag.

- [ ] Confirm `publish:crates` succeeds in the recovery pipeline.

## 5. Verify registries

- [ ] npm reports `@martin-wieser/locke` version `0.10.0`.
- [ ] crates.io reports `locke-creds` version `0.10.0`.
