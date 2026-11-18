// SPDX-License-Identifier: GPL-2.0-only
//! Measures how late a Windows high-resolution waitable timer fires when
//! driven at AWDL's availability-window period (16 TU = 16.384 ms), with each
//! wait aimed at an absolute deadline as Warlock's engine will do.
//!
//! Usage: timerjitter [periods=600] [period_us=16384]

use std::ffi::c_void;

const CREATE_WAITABLE_TIMER_HIGH_RESOLUTION: u32 = 0x2;
const TIMER_ALL_ACCESS: u32 = 0x1F_0003;
const INFINITE: u32 = 0xFFFF_FFFF;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateWaitableTimerExW(attrs: *const c_void, name: *const u16, flags: u32, access: u32) -> *mut c_void;
    fn SetWaitableTimer(
        timer: *mut c_void,
        due: *const i64,
        period: i32,
        routine: *const c_void,
        arg: *const c_void,
        resume: i32,
    ) -> i32;
    fn WaitForSingleObject(handle: *mut c_void, ms: u32) -> u32;
    fn QueryPerformanceCounter(count: *mut i64) -> i32;
    fn QueryPerformanceFrequency(freq: *mut i64) -> i32;
    fn CloseHandle(handle: *mut c_void) -> i32;
}

fn qpc() -> i64 {
    let mut c = 0;
    unsafe { QueryPerformanceCounter(&mut c) };
    c
}

fn main() {
    let mut args = std::env::args().skip(1);
    let periods: usize = args.next().map(|a| a.parse().expect("periods")).unwrap_or(600);
    let period_us: f64 = args.next().map(|a| a.parse().expect("period_us")).unwrap_or(16_384.0);

    let mut freq = 0;
    unsafe { QueryPerformanceFrequency(&mut freq) };
    let ticks_per_us = freq as f64 / 1e6;
    let timer = unsafe {
        CreateWaitableTimerExW(
            std::ptr::null(),
            std::ptr::null(),
            CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
            TIMER_ALL_ACCESS,
        )
    };
    assert!(!timer.is_null(), "CreateWaitableTimerExW failed (needs Windows 10 1803+)");

    let start = qpc();
    let mut late_us = Vec::with_capacity(periods);
    for i in 1..=periods {
        let deadline = start + (i as f64 * period_us * ticks_per_us) as i64;
        let remaining_us = (deadline - qpc()) as f64 / ticks_per_us;
        if remaining_us > 0.0 {
            // Negative due time = relative, in 100 ns units.
            let due = -((remaining_us * 10.0) as i64).max(1);
            unsafe {
                SetWaitableTimer(timer, &due, 0, std::ptr::null(), std::ptr::null(), 0);
                WaitForSingleObject(timer, INFINITE);
            }
        }
        late_us.push((qpc() - deadline) as f64 / ticks_per_us);
    }
    unsafe { CloseHandle(timer) };

    late_us.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let pct = |p: f64| late_us[((late_us.len() - 1) as f64 * p) as usize];
    let mean = late_us.iter().sum::<f64>() / late_us.len() as f64;
    println!(
        "{periods} waits at {:.3} ms: lateness mean {mean:.0} us, p50 {:.0} us, p90 {:.0} us, p99 {:.0} us, max {:.0} us",
        period_us / 1000.0,
        pct(0.5),
        pct(0.9),
        pct(0.99),
        late_us[late_us.len() - 1]
    );
    let over_1ms = late_us.iter().filter(|&&l| l > 1000.0).count();
    println!("waits more than 1 ms late: {over_1ms} ({:.1}%)", 100.0 * over_1ms as f64 / late_us.len() as f64);
}
