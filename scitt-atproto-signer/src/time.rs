//! A UTC timestamp, formatted as RFC 3339.
//!
//! One function, so that the `issuedAt` an attestation carries and the
//! `createdAt` a response reports are the same instant written the same way.
//! The civil-date arithmetic is Howard Hinnant's `civil_from_days`, which
//! needs no lookup table and is exact for the whole range of `i64` days.

use std::time::{SystemTime, UNIX_EPOCH};

/// The current time as an RFC 3339 UTC timestamp with milliseconds.
///
/// A clock before the Unix epoch -- which a misconfigured host can produce --
/// is reported as the epoch rather than as a negative year, because the
/// attestation layer expects `issuedAt` to be a plausible instant and a wrong
/// one is worse than an obviously stale one.
#[must_use]
pub fn now_rfc3339() -> String {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format_rfc3339(since_epoch.as_secs(), since_epoch.subsec_millis())
}

/// Format a Unix timestamp in seconds plus milliseconds as RFC 3339 UTC.
#[must_use]
pub fn format_rfc3339(seconds: u64, millis: u32) -> String {
    let days = (seconds / 86_400) as i64;
    let second_of_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = second_of_day / 3_600;
    let minute = (second_of_day % 3_600) / 60;
    let second = second_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// Days since 1970-01-01 to a proleptic Gregorian `(year, month, day)`.
///
/// Howard Hinnant's `civil_from_days`, shifting the epoch to 0000-03-01 so
/// that the leap day falls at the end of the cycle and the month lengths
/// become a simple pattern.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097; // [0, 146096]
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365; // [0, 399]
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153; // [0, 11]
    let day = u32::try_from(day_of_year - (153 * month_prime + 2) / 5 + 1).unwrap_or(1);
    let month = u32::try_from(if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    })
    .unwrap_or(1);
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known instants, including the epoch, a leap day, a century that is not
    /// a leap year, and the end of a year -- the four places this arithmetic
    /// goes wrong.
    #[test]
    fn known_instants_format_correctly() {
        assert_eq!(format_rfc3339(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(format_rfc3339(1, 0), "1970-01-01T00:00:01.000Z");
        // 2000-02-29 was a leap day in a century year that is a leap year.
        assert_eq!(format_rfc3339(951_782_400, 0), "2000-02-29T00:00:00.000Z");
        // 2100 is not: the day after 2100-02-28 is 2100-03-01.
        assert_eq!(format_rfc3339(4_107_542_400, 0), "2100-03-01T00:00:00.000Z");
        assert_eq!(format_rfc3339(4_107_456_000, 0), "2100-02-28T00:00:00.000Z");
        // One second before 2020 started.
        assert_eq!(
            format_rfc3339(1_577_836_799, 999),
            "2019-12-31T23:59:59.999Z"
        );
        assert_eq!(format_rfc3339(1_577_836_800, 0), "2020-01-01T00:00:00.000Z");
    }

    /// The formatter is used for `issuedAt`, so its output has to be the shape
    /// a consumer parses: fixed widths, a `T`, a `Z`, and milliseconds.
    #[test]
    fn now_is_well_formed_and_monotone() {
        let first = now_rfc3339();
        assert_eq!(first.len(), 24, "{first}");
        assert!(first.ends_with('Z'), "{first}");
        assert_eq!(&first[4..5], "-");
        assert_eq!(&first[10..11], "T");
        assert_eq!(&first[19..20], ".");

        let second = now_rfc3339();
        assert!(second >= first, "{second} is before {first}");
    }

    /// Every day of a leap year must round trip, which catches an off-by-one
    /// in the month-length pattern that a handful of spot checks would miss.
    #[test]
    fn every_day_of_a_leap_year_is_distinct_and_ordered() {
        /// 2000-01-01T00:00:00Z.
        const TWO_THOUSAND: u64 = 946_684_800;

        let mut seen = std::collections::BTreeSet::new();
        for day in 0..366u64 {
            let stamp = format_rfc3339(TWO_THOUSAND + day * 86_400, 0);
            assert!(seen.insert(stamp.clone()), "duplicate date {stamp}");
        }
        assert_eq!(seen.len(), 366);
        let first = seen.iter().next().expect("not empty");
        let last = seen.iter().next_back().expect("not empty");
        assert_eq!(first, "2000-01-01T00:00:00.000Z");
        assert_eq!(last, "2000-12-31T00:00:00.000Z");
    }
}
