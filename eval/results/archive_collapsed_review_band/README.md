# Archived results — score track reviewing everything (superseded)

The state of the system on 7 September 2026 before the operating-point correction.

`operating_thresholds.json` held `tau_review = 0.0`. Every risk estimate is >= 0, so the
score track proposed REVIEW for every query it ever saw, escalation dominance carried that
into the final action, and no query could be auto-accepted regardless of its evidence.

`clean_calibration_before.json` is the measurement that identified it: across 30 clean
control queries the score track closed on 30, and was the ONLY gate standing between the
query and GREEN on 15 of them. The band thresholds were not the constraint — clean
documents sat inside the CLEAN band on 97.1% (unsupport), 96.4% (anomaly), 100%
(injection) and 86.1% (conflict) of measurements.

Headline figures at this point: clean auto-accept 0.0% of documents and 0.0% of queries
against a structural ceiling of 90.0%; false positive rate 39.3%; attack success 60.0%
exposure and 0.0% vouched for.

Retained so the correction is visible rather than silent.
