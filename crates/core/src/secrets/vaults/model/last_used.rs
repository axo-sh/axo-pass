//! Local calendar day of a credential use.
//!
//! The system time zone comes from `jiff`, which reads `TZ` or
//! `/etc/localtime` and rechecks it every five minutes. The `time` crate
//! cannot read the local offset in a multithreaded process on macOS and falls
//! back to UTC. Tests call [`date_in_zone`] with an injected zone, since
//! setting `TZ` in a multithreaded test process is unsafe.

use jiff::Timestamp;
use jiff::civil::Date;
use jiff::tz::TimeZone;

/// Local calendar date at Unix time `unix`. `None` if the time is out of
/// range.
pub fn local_date(unix: i64) -> Option<Date> {
    date_in_zone(unix, TimeZone::system())
}

/// Calendar date at Unix time `unix` in `zone`. `None` if the time is out of
/// range.
pub fn date_in_zone(unix: i64, zone: TimeZone) -> Option<Date> {
    let at = Timestamp::from_second(unix).ok()?;
    Some(at.to_zoned(zone).date())
}

/// Whether a use at `at` falls on a later date in `zone` than the stored use
/// `stored`. True if no use is stored, or if the stored time is out of range.
/// False if `at` is out of range.
pub fn is_later_day(stored: Option<i64>, at: i64, zone: &TimeZone) -> bool {
    let Some(day) = date_in_zone(at, zone.clone()) else {
        return false;
    };
    match stored.and_then(|stored| date_in_zone(stored, zone.clone())) {
        Some(stored_day) => stored_day < day,
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use jiff::civil::date;
    use jiff::tz::Offset;

    use super::*;

    const HOUR: i32 = 3600;

    /// Unix time of 2026-10-23 00:00:00 UTC.
    const OCT_23_UTC: i64 = 1_792_713_600;

    fn fixed(seconds: i32) -> TimeZone {
        TimeZone::fixed(Offset::from_seconds(seconds).unwrap())
    }

    #[test]
    fn zone_west_of_utc_gives_previous_date() {
        let zone = fixed(-7 * HOUR);
        // 2026-10-22 23:59:59 at UTC-7.
        let before = OCT_23_UTC + 7 * 3600 - 1;
        assert_eq!(date_in_zone(before, zone.clone()), Some(date(2026, 10, 22)));
        // 2026-10-23 00:00:00 at UTC-7.
        assert_eq!(date_in_zone(before + 1, zone), Some(date(2026, 10, 23)));
        // UTC is already on 2026-10-23 at both times.
        assert_eq!(
            date_in_zone(before, TimeZone::UTC),
            Some(date(2026, 10, 23))
        );
    }

    #[test]
    fn zone_east_of_utc_gives_next_date_after_its_midnight() {
        let offset = 9 * HOUR + 30 * 60;
        let zone = fixed(offset);
        // 2026-10-23 23:59:59 at UTC+9:30.
        let before = OCT_23_UTC + 24 * 3600 - i64::from(offset) - 1;
        assert_eq!(date_in_zone(before, zone.clone()), Some(date(2026, 10, 23)));
        // 2026-10-24 00:00:00 at UTC+9:30.
        assert_eq!(date_in_zone(before + 1, zone), Some(date(2026, 10, 24)));
        // UTC is still on 2026-10-23 at both times.
        assert_eq!(
            date_in_zone(before + 1, TimeZone::UTC),
            Some(date(2026, 10, 23))
        );
    }

    #[test]
    fn named_zone_follows_daylight_saving_time() {
        let zone = TimeZone::get("America/New_York").unwrap();
        // 2026-07-01 03:59:59 UTC is 23:59:59 on June 30 at UTC-4 (EDT).
        let july = 1_782_878_400 - 1;
        assert_eq!(date_in_zone(july, zone.clone()), Some(date(2026, 6, 30)));
        assert_eq!(date_in_zone(july + 1, zone.clone()), Some(date(2026, 7, 1)));
        // 2026-12-01 04:59:59 UTC is 23:59:59 on November 30 at UTC-5 (EST).
        let december = 1_796_101_200 - 1;
        assert_eq!(
            date_in_zone(december, zone.clone()),
            Some(date(2026, 11, 30))
        );
        assert_eq!(date_in_zone(december + 1, zone), Some(date(2026, 12, 1)));
    }

    #[test]
    fn time_out_of_range_gives_no_date() {
        assert_eq!(date_in_zone(i64::MAX, TimeZone::UTC), None);
    }

    #[test]
    fn use_with_no_stored_use_is_later_day() {
        assert!(is_later_day(None, OCT_23_UTC, &TimeZone::UTC));
        assert!(is_later_day(Some(i64::MAX), OCT_23_UTC, &TimeZone::UTC));
        assert!(!is_later_day(None, i64::MAX, &TimeZone::UTC));
    }

    #[test]
    fn uses_either_side_of_local_midnight_are_on_different_days() {
        let zone = fixed(-7 * HOUR);
        // 2026-10-22 23:30 and 2026-10-23 00:30 at UTC-7. Both are on
        // 2026-10-23 in UTC.
        let before = OCT_23_UTC + 7 * 3600 - 1800;
        let after = before + 3600;
        assert!(is_later_day(Some(before), after, &zone));
        assert!(!is_later_day(Some(before), after, &TimeZone::UTC));
    }

    #[test]
    fn utc_midnight_inside_local_day_is_same_day() {
        let zone = fixed(-7 * HOUR);
        // 2026-10-22 16:30 and 17:30 at UTC-7, either side of UTC midnight.
        let before = OCT_23_UTC - 1800;
        let after = before + 3600;
        assert!(!is_later_day(Some(before), after, &zone));
        assert!(is_later_day(Some(before), after, &TimeZone::UTC));
    }

    #[test]
    fn use_on_earlier_day_not_later_day() {
        let zone = fixed(9 * HOUR);
        assert!(!is_later_day(Some(OCT_23_UTC + 86_400), OCT_23_UTC, &zone));
        assert!(is_later_day(Some(OCT_23_UTC), OCT_23_UTC + 86_400, &zone));
    }
}
