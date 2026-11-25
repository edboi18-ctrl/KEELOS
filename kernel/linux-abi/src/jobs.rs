//! Process groups and sessions (P3-T12 part 2; ADR 0030): setpgid,
//! getpgid, getpgrp, setsid and getsid, signals to a group, and the
//! orphaned-group test job control needs.
//!
//! The rules are Linux v6.12's (`kernel/sys.c`, `kernel/exit.c`'s
//! `will_become_orphaned_pgrp`, `kernel/signal.c`'s `kill_something_info`
//! and `__kill_pgrp_info`). Group and session IDs are PIDs of the
//! process's compartment, which never reuses a PID (ADR 0014), so a
//! number names one group or session for good. A process the kernel
//! starts is in session 0 and group 0, as Linux's init begins.
//!
//! Linux keeps a zombie in its group until it is reaped; Keel's lookups
//! see running processes only, so a group of zombies is empty here.

use alloc::sync::Arc;
use alloc::vec::Vec;

use keel_core::compartment::Compartment;
use keel_core::errno::Errno;
use keel_core::signal::SigInfo;
use keel_hal::sync::IrqMutex;

use crate::process::{self, Process};

type ProcessRef = Arc<IrqMutex<Process>>;
type SysResult = Result<u64, Errno>;

fn compartment_of(p: &ProcessRef) -> Arc<Compartment> {
    p.lock().member.compartment().clone()
}

/// The process `pid` names in `compartment`: a process with that PID, or
/// the process one of whose threads has that TID (`find_task_by_vpid`
/// finds any task). The flag says it is a thread other than the first.
fn task(compartment: &Arc<Compartment>, pid: u32) -> Option<(ProcessRef, bool)> {
    if let Some(p) = process::find_in(compartment, pid) {
        return Some((p, false));
    }
    process::find_thread(compartment, pid).map(|(p, _)| (p, true))
}

/// setpgid(2) (`kernel/sys.c`): `pid` 0 is the caller, `pgid` 0 is `pid`;
/// a negative `pgid` is EINVAL. The target must be the caller or a child
/// of it (ESRCH), and a process, not another thread (EINVAL); a child in
/// another session is EPERM, one that has called execve EACCES; a session
/// leader EPERM. Joining another group needs a member of it in the
/// caller's session (EPERM).
pub fn setpgid(p: &ProcessRef, pid: i32, pgid: i32) -> SysResult {
    let (me, my_sid, compartment) = {
        let q = p.lock();
        (q.pid(), q.sid, q.member.compartment().clone())
    };
    let pid = if pid == 0 { me } else { pid as u32 };
    let pgid = if pgid == 0 { pid as i32 } else { pgid };
    if pgid < 0 {
        return Err(Errno::EINVAL);
    }
    let pgid = pgid as u32;
    // A child that has exited and is not reaped yet is still found
    // (`find_task_by_vpid`: its PID link lasts until `release_task`), and
    // its group can still change.
    let zombie = || {
        p.lock()
            .children
            .iter()
            .find(|c| c.pid == pid && c.status.is_some())
            .map(|c| c.process.clone())
    };
    let (target, thread, zombie) = match task(&compartment, pid) {
        Some((t, thread)) => (t, thread, false),
        None => (zombie().ok_or(Errno::ESRCH)?, false, true),
    };
    if thread {
        return Err(Errno::EINVAL);
    }
    let (child, sid, execed, leader) = {
        let t = target.lock();
        let child = zombie
            || t.parent
                .as_ref()
                .and_then(alloc::sync::Weak::upgrade)
                .is_some_and(|parent| Arc::ptr_eq(&parent, p));
        (child, t.sid, t.execed, t.leader)
    };
    if child {
        if sid != my_sid {
            return Err(Errno::EPERM);
        }
        if execed {
            return Err(Errno::EACCES);
        }
    } else if !Arc::ptr_eq(&target, p) {
        return Err(Errno::ESRCH);
    }
    if leader {
        return Err(Errno::EPERM);
    }
    if pgid != pid {
        // pid_task(pgrp, PIDTYPE_PGID): a member, in the caller's session
        // (a group's members share one).
        // A zombie counts: it stays in its group until reaped.
        let pick = |q: &Process| q.pgid == pgid && q.sid == my_sid;
        let joinable = !process::members(&compartment, pick).is_empty()
            || !process::zombies(&compartment, pick).is_empty();
        if !joinable {
            return Err(Errno::EPERM);
        }
    }
    target.lock().pgid = pgid;
    Ok(0)
}

/// getpgid(2): the group of `pid` (0: the caller); ESRCH if none.
pub fn getpgid(p: &ProcessRef, pid: i32) -> SysResult {
    if pid == 0 {
        return Ok(u64::from(p.lock().pgid));
    }
    let (target, _) = task(&compartment_of(p), pid as u32).ok_or(Errno::ESRCH)?;
    let pgid = target.lock().pgid;
    Ok(u64::from(pgid))
}

/// getsid(2): the session of `pid` (0: the caller); ESRCH if none.
pub fn getsid(p: &ProcessRef, pid: i32) -> SysResult {
    if pid == 0 {
        return Ok(u64::from(p.lock().sid));
    }
    let (target, _) = task(&compartment_of(p), pid as u32).ok_or(Errno::ESRCH)?;
    let sid = target.lock().sid;
    Ok(u64::from(sid))
}

/// setsid(2) (`ksys_setsid`): EPERM for a session leader, or if a group
/// with the caller's PID exists; otherwise the caller leads a new session
/// and group, both its PID, with no controlling terminal.
pub fn setsid(p: &ProcessRef) -> SysResult {
    let (me, leader, compartment) = {
        let q = p.lock();
        (q.pid(), q.leader, q.member.compartment().clone())
    };
    if leader || !process::members(&compartment, |q| q.pgid == me).is_empty() {
        return Err(Errno::EPERM);
    }
    let mut q = p.lock();
    q.leader = true;
    q.sid = me;
    q.pgid = me;
    q.ctty = None;
    q.old_pgrp = None;
    Ok(u64::from(me))
}

/// Sends `info` to every running process of group `pgid` in `compartment`
/// (`__kill_pgrp_info`); signal 0 sends nothing. ESRCH for an empty group.
pub fn kill_group(compartment: &Arc<Compartment>, pgid: u32, info: SigInfo) -> Result<(), Errno> {
    let members = process::members(compartment, |q| q.pgid == pgid);
    // A group of zombies only still exists (`__kill_pgrp_info` finds them
    // until they are reaped): the signal is accepted and goes nowhere.
    if members.is_empty() && process::zombies(compartment, |q| q.pgid == pgid).is_empty() {
        return Err(Errno::ESRCH);
    }
    if info.signo != 0 {
        for m in &members {
            crate::signal::send_to_process(m, info);
        }
    }
    Ok(())
}

/// kill(2) with PID -1 (`kill_something_info`): every process of the
/// caller's compartment but its PID 1 and the caller. ESRCH if there is
/// none.
pub fn kill_all(p: &ProcessRef, info: SigInfo) -> Result<(), Errno> {
    let compartment = compartment_of(p);
    let me = p.lock().pid();
    let targets = process::members(&compartment, |q| q.pid() > 1 && q.pid() != me);
    if targets.is_empty() {
        return Err(Errno::ESRCH);
    }
    if info.signo != 0 {
        for t in &targets {
            crate::signal::send_to_process(t, info);
        }
    }
    Ok(())
}

/// A signal from the kernel (`kill_pgrp(pgrp, sig, 1)`: SEND_SIG_PRIV,
/// so `si_code` SI_KERNEL) to group `pgid`; nothing if it is empty.
pub fn signal_group(compartment: &Arc<Compartment>, pgid: u32, signal: i32) {
    let _ = kill_group(compartment, pgid, SigInfo::kernel(signal));
}

/// The running processes of session `sid` in `compartment`.
pub fn session_members(compartment: &Arc<Compartment>, sid: u32) -> Vec<ProcessRef> {
    process::members(compartment, |q| q.sid == sid)
}

/// Whether group `pgid` is orphaned (`will_become_orphaned_pgrp` with no
/// task left out): no member has a parent in another group of the same
/// session. A member whose parent is gone, or is the compartment's PID 1,
/// does not count (Linux reparents an orphan to init and skips init's
/// children).
pub fn orphaned(compartment: &Arc<Compartment>, pgid: u32) -> bool {
    orphaned_without(compartment, pgid, None)
}

/// As [`orphaned`], with `gone` (an exiting process) counted as no
/// parent.
fn orphaned_without(compartment: &Arc<Compartment>, pgid: u32, gone: Option<&ProcessRef>) -> bool {
    let members = process::members(compartment, |q| q.pgid == pgid);
    for m in members {
        if gone.is_some_and(|g| Arc::ptr_eq(g, &m)) {
            continue;
        }
        let (parent, sid) = {
            let q = m.lock();
            (
                q.parent.as_ref().and_then(alloc::sync::Weak::upgrade),
                q.sid,
            )
        };
        let Some(parent) = parent else {
            continue;
        };
        if gone.is_some_and(|g| Arc::ptr_eq(g, &parent)) {
            continue;
        }
        let parent = parent.lock();
        if parent.pid() == 1 {
            continue;
        }
        if parent.pgid != pgid && parent.sid == sid {
            return false;
        }
    }
    true
}

/// `has_stopped_jobs`: a member of group `pgid` is stopped.
fn has_stopped(compartment: &Arc<Compartment>, pgid: u32) -> bool {
    !process::members(compartment, |q| q.pgid == pgid && q.stopped).is_empty()
}

/// `kill_orphaned_pgrp` at an exit (`exit_notify`, `reparent_leader`): a
/// group the exit leaves orphaned that has a stopped member gets SIGHUP
/// and SIGCONT (as the kernel), so its jobs do not stay stopped with no
/// one to continue them. That is the exiting process's own group, if its
/// parent was in another group of its session, and each live child's
/// group in another group of its session.
pub fn orphan_at_exit(exiting: &ProcessRef, parent: Option<&ProcessRef>, children: &[ProcessRef]) {
    let (compartment, pgid, sid) = {
        let q = exiting.lock();
        (q.member.compartment().clone(), q.pgid, q.sid)
    };
    let hang_up = |group: u32| {
        signal_group(&compartment, group, keel_core::signal::SIGHUP);
        signal_group(&compartment, group, keel_core::signal::SIGCONT);
    };
    let mut groups: Vec<u32> = Vec::new();
    if let Some(parent) = parent {
        let (ppgid, psid) = {
            let q = parent.lock();
            (q.pgid, q.sid)
        };
        if ppgid != pgid && psid == sid {
            groups.push(pgid);
        }
    }
    for child in children {
        let (cpgid, csid) = {
            let q = child.lock();
            (q.pgid, q.sid)
        };
        if cpgid != pgid && csid == sid && !groups.contains(&cpgid) {
            groups.push(cpgid);
        }
    }
    for group in groups {
        if orphaned_without(&compartment, group, Some(exiting)) && has_stopped(&compartment, group)
        {
            hang_up(group);
        }
    }
}
