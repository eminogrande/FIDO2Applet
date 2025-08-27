Backups (git bundles)

- feat-prf-support: feat-prf-support-2025-08-26.bundle
- main (integration snapshot): main-integration-2025-08-26.bundle

Restore examples:

# Clone from bundle
mkdir restore && cd restore
git clone ../backups/feat-prf-support-2025-08-26.bundle prf-repo
cd prf-repo
# list branches in bundle
git branch -a
# create branch from bundle tip (if needed)
git checkout -b feat/prf-support

# To fetch into existing repo
git remote add backup-prf ../backups/feat-prf-support-2025-08-26.bundle
git fetch backup-prf 'refs/heads/*:refs/remotes/backup-prf/*'
