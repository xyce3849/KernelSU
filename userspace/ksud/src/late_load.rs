use anyhow::{Context, Result};
use log::{info, warn};
use rustix::cstr;
use std::{process::Command, thread::sleep, time::{Duration, Instant}};

use crate::module::{ScriptWait, handle_updated_modules, prune_modules};
use crate::{assets, defs, init_event, metamodule, restorecon, utils};

fn dump_process_info(label: &str) {
    use rustix::process::{getgid, getgroups, getpid, getuid};

    let pid = getpid().as_raw_nonzero();
    let uid = getuid().as_raw();
    let gid = getgid().as_raw();
    let groups: Vec<String> = getgroups()
        .unwrap_or_default()
        .iter()
        .map(|g| g.as_raw().to_string())
        .collect();
    let selinux = std::fs::read_to_string("/proc/self/attr/current")
        .unwrap_or_else(|_| "unknown".to_string());
    let seccomp = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Seccomp:"))
                .map(|l| l.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());

    info!(
        "[{label}] pid={pid}, uid={uid}, gid={gid}, groups=[{}], selinux={}, {seccomp}",
        groups.join(","),
        selinux.trim(),
    );
}

pub fn run(package_name: &String, kmi: Option<String>, allow_shell: bool) -> Result<()> {
    utils::daemonize(false)?;
    info!("late-load command triggered!");
    dump_process_info("late-load start");

    // 1. Check if KernelSU is already loaded
    if ksuinit::has_kernelsu() {
        info!("KernelSU already loaded, skip loading ko");
    } else {
        // 2. Detect current KMI version
        let kmi = kmi.map_or_else(
            || crate::boot_patch::get_current_kmi().context("Failed to detect current KMI version"),
            Ok,
        )?;
        info!("Detected KMI: {kmi}");

        // 3. Get kernelsu.ko from embedded assets
        let ko_name = format!("{kmi}_kernelsu.ko");
        let ko_data = assets::get_asset_data(&ko_name)
            .with_context(|| format!("Failed to get {ko_name} from assets"))?;

        // 4. Load kernelsu.ko from memory with manual relocation
        info!("Loading kernelsu.ko for KMI {kmi}...");
        // bundled flag is meaningless in jailbreak mode since we can't flash boot to update it.
        let params = if allow_shell {
            cstr!("allow_shell=1")
        } else {
            cstr!("")
        };
        ksuinit::load_module(&ko_data, params).context("Failed to load kernelsu.ko")?;
        info!("kernelsu.ko loaded successfully!");
        dump_process_info("after load_module");
    }

    // We need to reset stdin/stdout/stderr; otherwise, sending file descriptors via cmd transactions
    // will be blocked by SELinux because its fsec->sid is still u:r:su:s0 instead of u:r:ksu:s0.
    utils::reset_std()?;

    utils::umask(0);

    if let Err(e) = crate::module_config::clear_all_temp_configs() {
        warn!("clear temp configs failed: {e}");
    }

    utils::install(None, None).context("Failed to install ksud")?;

    // 5. Handle module updates
    if let Err(e) = handle_updated_modules() {
        warn!("handle updated modules failed: {e}");
    }

    if let Err(e) = prune_modules() {
        warn!("prune modules failed: {e}");
    }

    if let Err(e) = restorecon::restorecon() {
        warn!("restorecon failed: {e}");
    }

    // 6. Load SELinux rules
    if crate::module::load_sepolicy_rule().is_err() {
        warn!("load sepolicy.rule failed");
    }

    if let Err(e) = crate::profile::apply_sepolies() {
        warn!("apply root profile sepolicy failed: {e}");
    }

    // 7. Initialize features
    if let Err(e) = crate::feature::init_features() {
        warn!("init features failed: {e}");
    }

    // 8. Execute late-load stage scripts with a shared boot deadline
    let wait = ScriptWait::Until(Instant::now() + defs::BOOT_STAGE_TIMEOUT);
    init_event::run_stage("late-load", wait);

    // 9. Load system.prop
    if let Err(e) = crate::module::load_system_prop() {
        warn!("load system.prop failed: {e}");
    }

    // 10. Execute metamodule mount script (OverlayFS)
    if let Err(e) = metamodule::exec_mount_script(defs::MODULE_DIR) {
        warn!("execute metamodule mount failed: {e}");
    }

    // 11. Execute post-mount stage scripts using the same deadline
    init_event::run_stage("post-mount", wait);

    // 12. Execute service stage scripts (non-blocking)
    init_event::run_stage("service", ScriptWait::NoWait);

    // 13. Execute boot-completed stage scripts (non-blocking)
    init_event::run_stage("boot-completed", ScriptWait::NoWait);

    // 14. Restart Manager so it gets a fresh ksu fd from the newly loaded kernel module.
    // The Java/Kotlin namespace may differ from the APK applicationId, so resolve
    // the launcher activity by package instead of constructing a class name.
    info!("Restarting KernelSU Manager {package_name}...");

    match Command::new("am")
        .args(["force-stop", package_name])
        .status()
    {
        Ok(status) if status.success() => {}
        Ok(status) => warn!("am force-stop returned {status} for Manager {package_name}"),
        Err(e) => warn!("failed to force-stop Manager {package_name}: {e}"),
    }

    sleep(Duration::from_millis(250));

    let mut restarted = false;
    for attempt in 1..=5 {
        let result = Command::new("am")
            .args([
                "start", "-W", "-a", "android.intent.action.MAIN",
                "-c", "android.intent.category.LAUNCHER", "-p", package_name,
            ])
            .output();
        match result {
            Ok(output) if output.status.success() => {
                info!("KernelSU Manager {package_name} restarted on attempt {attempt}");
                restarted = true;
                break;
            }
            Ok(output) => warn!(
                "Manager restart attempt {attempt} failed: status={}, stdout={}, stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stdout).trim(),
                String::from_utf8_lossy(&output.stderr).trim(),
            ),
            Err(e) => warn!("failed to execute ActivityManager on attempt {attempt}: {e}"),
        }
        sleep(Duration::from_millis(300));
    }

    if !restarted {
        // Compatibility fallback: ask PackageManager for the actual launcher
        // component, then start that component explicitly.
        match Command::new("cmd")
            .args(["package", "resolve-activity", "--brief", package_name])
            .output()
        {
            Ok(output) if output.status.success() => {
                let component = String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .map(str::trim)
                    .find(|line| line.contains('/'))
                    .unwrap_or_default()
                    .to_string();
                if component.is_empty() {
                    warn!("PackageManager returned no launcher component for {package_name}");
                } else {
                    match Command::new("am").args(["start", "-W", "-n", &component]).status() {
                        Ok(status) if status.success() => {
                            info!("KernelSU Manager restarted using resolved component {component}");
                        }
                        Ok(status) => warn!("resolved Manager component failed to start: {status}"),
                        Err(e) => warn!("failed to start resolved Manager component: {e}"),
                    }
                }
            }
            Ok(output) => warn!(
                "failed to resolve Manager launcher: status={}, stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim(),
            ),
            Err(e) => warn!("failed to execute PackageManager resolver: {e}"),
        }
    }

    Ok(())
}
