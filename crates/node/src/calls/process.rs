//! Platformová vrstva spravovaného potomka: väzba životnosti na uzol,
//! graceful stop a súkromné zápisy súborov s tajomstvami.
//!
//! - **Linux:** `prctl(PR_SET_PDEATHSIG, SIGTERM)` v `pre_exec` — keď uzol
//!   zomrie (aj `kill -9`), kernel pošle LiveKitu SIGTERM. Pozor: signál sa
//!   viaže na **vlákno**, ktoré forkovalo. Spawn preto robí supervízor na
//!   tokio worker vlákne (žije s runtime), nikdy nie v `spawn_blocking`
//!   (blocking vlákna po nečinnosti končia → potomok by dostal SIGTERM).
//!   Potomok má vlastnú skupinu procesov, aby Ctrl-C v termináli nešlo
//!   priamo jemu — zastavuje ho uzol ([`terminate`]).
//! - **Windows:** Job Object s `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`; handle
//!   drží [`ChildGuard`]. Keď uzol skončí (aj pádom), OS handle zavrie a
//!   potomka zabije.

use std::io;
use std::path::Path;
use std::time::Duration;
use tokio::process::{Child, Command};

/// Ako dlho čakať na dobrovoľné ukončenie po SIGTERM.
const GRACEFUL_STOP: Duration = Duration::from_secs(10);

/// Zápis súboru s tajomstvom: `tmp` + rename, na unixe práva 0600.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        io::Write::write_all(&mut f, bytes)?;
        f.sync_all()?;
    }
    #[cfg(unix)]
    {
        // `mode` platí len pri vytvorení — starý tmp mohol mať iné práva
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, path)
}

/// Práva na spustenie (unix 0755; Windows nepotrebuje).
pub(crate) fn make_executable(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Nastav príkaz pred spawnom (väzba na rodiča, skupina procesov).
pub(crate) fn configure(cmd: &mut Command) {
    cmd.kill_on_drop(true);
    #[cfg(unix)]
    {
        cmd.process_group(0);
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: closure beží v potomkovi medzi fork a exec; volá len
        // async-signal-safe funkcie (prctl, getppid) a nealokuje.
        let parent = std::process::id() as libc::pid_t;
        unsafe {
            cmd.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM, 0, 0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                // rodič mohol zomrieť ešte pred prctl — potom signál nepríde
                if libc::getppid() != parent {
                    return Err(io::Error::other("rodič (uzol) už neexistuje"));
                }
                Ok(())
            });
        }
    }
}

/// Drží väzbu potomka na uzol (Windows: Job Object handle).
pub(crate) struct ChildGuard {
    #[cfg(windows)]
    job: win::Job,
}

/// Pripoj spusteného potomka k uzlu. Na Linuxe je väzba už v `pre_exec`.
pub(crate) fn attach(child: &Child) -> io::Result<ChildGuard> {
    #[cfg(windows)]
    {
        let handle = child
            .raw_handle()
            .ok_or_else(|| io::Error::other("potomok už skončil"))?;
        let job = win::Job::kill_on_close()?;
        job.assign(handle)?;
        Ok(ChildGuard { job })
    }
    #[cfg(not(windows))]
    {
        let _ = child;
        Ok(ChildGuard {})
    }
}

/// Graceful stop: unix SIGTERM → čakať [`GRACEFUL_STOP`] → SIGKILL.
/// Windows: konzolová aplikácia bez okna nemá spoľahlivý „SIGTERM“, preto
/// TerminateProcess (+ zavretie jobu, keď sa `_guard` na konci zahodí).
pub(crate) async fn terminate(child: &mut Child, _guard: ChildGuard) {
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        // SAFETY: kill(2) na pid nášho ešte nezreapovaného potomka
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGTERM);
        }
        match tokio::time::timeout(GRACEFUL_STOP, child.wait()).await {
            Ok(Ok(status)) => {
                tracing::info!(target: "livekit", %status, "LiveKit ukončený (SIGTERM)");
                return;
            }
            Ok(Err(e)) => {
                tracing::warn!(target: "livekit", error = %e, "čakanie na LiveKit zlyhalo")
            }
            Err(_) => {
                tracing::warn!(target: "livekit", "LiveKit nereagoval na SIGTERM do 10 s — SIGKILL")
            }
        }
    }
    if let Err(e) = child.kill().await {
        tracing::warn!(target: "livekit", error = %e, "zabitie LiveKit procesu zlyhalo");
    }
}

#[cfg(windows)]
mod win {
    use std::io;
    use std::os::windows::io::RawHandle;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };

    /// Vlastnený handle Job Objectu; drop = CloseHandle = zabitie potomkov.
    pub(super) struct Job(HANDLE);

    // SAFETY: HANDLE je len identifikátor kernel objektu; používame ho z
    // jedného tasku naraz a zatvárame raz (Drop).
    unsafe impl Send for Job {}
    unsafe impl Sync for Job {}

    impl Job {
        pub(super) fn kill_on_close() -> io::Result<Self> {
            // SAFETY: štandardné Win32 volania s platnými argumentmi;
            // výsledok kontrolujeme a pri chybe handle zatvoríme.
            unsafe {
                let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
                if job.is_null() {
                    return Err(io::Error::last_os_error());
                }
                let job = Job(job);
                let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                let ok = SetInformationJobObject(
                    job.0,
                    JobObjectExtendedLimitInformation,
                    &info as *const _ as *const core::ffi::c_void,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                );
                if ok == 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(job)
            }
        }

        pub(super) fn assign(&self, process: RawHandle) -> io::Result<()> {
            // SAFETY: `process` je platný handle živého potomka (tokio Child)
            let ok = unsafe { AssignProcessToJobObject(self.0, process as HANDLE) };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }

    impl Drop for Job {
        fn drop(&mut self) {
            // SAFETY: handle vlastníme a zatvárame práve raz
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_private_replaces_atomically() {
        let dir = std::env::temp_dir().join(format!(
            "myhsn-calls-proc-{}",
            myhsn_core::record::to_hex(&crate::auth::random_32())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("livekit.yaml");
        write_private(&p, b"a").unwrap();
        write_private(&p, b"bb").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"bb");
        assert!(!dir.join("livekit.tmp").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SIGTERM sa doručí a potomok skončí bez SIGKILL (unix).
    #[cfg(unix)]
    #[tokio::test]
    async fn terminate_stops_child_with_sigterm() {
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        configure(&mut cmd);
        let mut child = cmd.spawn().unwrap();
        let guard = attach(&child).unwrap();
        let t0 = std::time::Instant::now();
        terminate(&mut child, guard).await;
        assert!(t0.elapsed() < Duration::from_secs(5), "SIGTERM má stačiť");
        assert!(child.try_wait().unwrap().is_some());
    }
}
