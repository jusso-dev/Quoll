use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// UTC timestamp in RFC 3339, the format SARIF and the JSON report both require.
pub fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// Unix epoch seconds, used as the SQLite storage form.
pub fn now_unix() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

pub fn unix_to_rfc3339(seconds: i64) -> String {
    OffsetDateTime::from_unix_timestamp(seconds)
        .ok()
        .and_then(|t| t.format(&Rfc3339).ok())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
}

/// Human-friendly duration for terminal output: `1.2s`, `340ms`, `2m 5s`.
pub fn humanise(duration: std::time::Duration) -> String {
    let millis = duration.as_millis();
    if millis < 1_000 {
        format!("{millis}ms")
    } else if millis < 60_000 {
        format!("{:.1}s", duration.as_secs_f64())
    } else {
        let secs = duration.as_secs();
        format!("{}m {}s", secs / 60, secs % 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn formats_durations_by_magnitude() {
        assert_eq!(humanise(Duration::from_millis(340)), "340ms");
        assert_eq!(humanise(Duration::from_millis(1200)), "1.2s");
        assert_eq!(humanise(Duration::from_secs(125)), "2m 5s");
    }

    #[test]
    fn epoch_round_trips() {
        assert_eq!(unix_to_rfc3339(0), "1970-01-01T00:00:00Z");
    }
}
