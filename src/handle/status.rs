use std::io::{stdout, Write};
use std::thread;
use std::time::Duration;
const STATUS_SIZE: usize = 35;

pub(crate) fn status(status: &str) {
    let filln = STATUS_SIZE - status.len();
    let fill = if filln > 0 {
        " ".repeat(filln)
    } else {
        "".to_string()
    };
    print!("\r{}{}", status, fill);
    let mut stdout = stdout();
    stdout.flush().unwrap();
    thread::sleep(Duration::from_millis(85));
}
