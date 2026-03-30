use crate::Finding;

pub fn print_json(findings: &[Finding]) {
    let json = serde_json::to_string_pretty(findings).expect("Failed to serialize findings");
    println!("{}", json);
}
