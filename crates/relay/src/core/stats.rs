//! The gauges of the metrics page (DESIGN.md "Monitoring and alerting"
//! signals 3 and 4), read from the data directory at each scrape.

use std::path::Path;

use rusqlite::params;

use super::{Relay, compact, from_i64, safe_name, user};
use crate::metrics::{Gauges, at_least};
use crate::store::{self, Kind, StoreError};

/// The bytes of each file under `dir`. A file that goes away during the
/// walk counts as 0.
fn dir_bytes(dir: &Path) -> u64 {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    rd.flatten()
        .map(|e| match e.metadata() {
            Ok(m) if m.is_dir() => dir_bytes(&e.path()),
            Ok(m) => m.len(),
            Err(_) => 0,
        })
        .fold(0, u64::saturating_add)
}

impl Relay {
    /// The metrics page (`snailfish-relay serve --metrics-listen`).
    ///
    /// # Errors
    ///
    /// A storage failure.
    pub fn metrics_text(&self) -> Result<String, StoreError> {
        Ok(crate::metrics::render(&self.gauges()?))
    }

    fn gauges(&self) -> Result<Gauges, StoreError> {
        let mut g = Gauges::default();
        let d = self.directory()?;
        let mut st = d.prepare("SELECT name, tenant_id FROM users ORDER BY name")?;
        let users: Vec<(String, String)> = st
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?;
        drop(st);
        drop(d);
        for (name, id) in users {
            let t = self.tenant_by_id(id)?;
            g.tenant_bytes.insert(name, dir_bytes(&t.dir));
            let tc = store::open(&t.db(), Kind::Tenant, false)?;
            let quota = user::limits(&tc, &self.cfg.quotas)?.space_bytes;
            let mut st = tc.prepare("SELECT file_name FROM spaces WHERE status = 'active'")?;
            let files: Vec<String> = st
                .query_map(params![], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            for f in files.iter().filter(|f| safe_name(f, 26)) {
                let c = store::open(
                    &t.dir.join("spaces").join(format!("{f}.db")),
                    Kind::Space,
                    false,
                )?;
                let used =
                    from_i64(
                        c.query_row("SELECT bytes FROM usage WHERE id = 1", [], |r| r.get(0))?,
                    )?;
                let security = from_i64(c.query_row(
                    "SELECT bytes FROM security_usage WHERE id = 1",
                    [],
                    |r| r.get(0),
                )?)?;
                let (stubs, bytes) = compact::stub_usage(&c)?;
                g.above_80 = g
                    .above_80
                    .saturating_add(u64::from(at_least(used, quota, 8, 10)));
                g.above_95 = g
                    .above_95
                    .saturating_add(u64::from(at_least(used, quota, 95, 100)));
                g.reserve_50 = g.reserve_50.saturating_add(u64::from(at_least(
                    security,
                    self.cfg.security_reserve,
                    1,
                    2,
                )));
                g.stubs = g.stubs.saturating_add(stubs);
                g.stub_bytes = g.stub_bytes.saturating_add(bytes);
                g.stubs_max = g.stubs_max.max(stubs);
            }
        }
        if let Ok(s) = rustix::fs::statvfs(&self.cfg.data_dir) {
            g.free_bytes = s.f_bavail.saturating_mul(s.f_frsize);
            g.size_bytes = s.f_blocks.saturating_mul(s.f_frsize);
        }
        Ok(g)
    }
}
