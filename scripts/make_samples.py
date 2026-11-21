"""Create sample flow files for trying the dashboard (and for Phase 6 tests).

Run from the project folder (after scripts/train_models.py):
    python scripts/make_samples.py

Every sample row is an original CICIDS2017 row (all 85 columns, original
headers) whose feature record belongs to the held-out test set, so the
saved model never saw these records during training.

    sample_mixed.csv       3,000 benign + 1,000 port scan flows
    sample_benign_only.csv 2,000 benign flows (expect no scans)
    sample_scan_only.csv   500 port scan flows
    sample_invalid.csv     a file with the wrong columns (expect an error)
"""

import numpy as np
import pandas as pd

from portscan import config
from portscan.preprocessing import load_raw_dataset, to_numeric_features

SEED = config.RANDOM_STATE


def main():
    raw = load_raw_dataset()                    # headers stripped for matching
    original = pd.read_csv(config.RAW_DATASET_PATH, encoding="latin1", low_memory=False, nrows=0)
    test = pd.read_csv(config.PROCESSED_DIR / "test_set.csv")

    X = to_numeric_features(raw)
    keys = pd.MultiIndex.from_frame(X.assign(Label=raw["Label"].str.strip()))
    test_keys = pd.MultiIndex.from_frame(test[config.FEATURES].astype("float64").assign(Label=test["Label"]))
    unseen = raw[keys.isin(test_keys)]
    benign = unseen[unseen["Label"] == config.BENIGN_LABEL]
    scans = unseen[unseen["Label"] == config.PORTSCAN_LABEL]
    print(f"Raw rows whose records are in the test set: {len(unseen):,} "
          f"(benign {len(benign):,}, scan {len(scans):,})")

    def write(df, name):
        df = df.copy()
        df.columns = original.columns           # restore the original CICIDS2017 headers
        df.to_csv(config.SAMPLES_DIR / name, index=False)
        print(f"  {name:<24} {len(df):>6,} rows")

    rng = np.random.default_rng(SEED)
    mixed = pd.concat([benign.sample(3000, random_state=SEED),
                       scans.sample(min(1000, len(scans)), random_state=SEED)])
    write(mixed.iloc[rng.permutation(len(mixed))], "sample_mixed.csv")
    write(benign.sample(2000, random_state=SEED + 1), "sample_benign_only.csv")
    write(scans.sample(min(500, len(scans)), random_state=SEED + 2), "sample_scan_only.csv")
    pd.DataFrame({"student": ["A", "B"], "score": [70, 85]}).to_csv(
        config.SAMPLES_DIR / "sample_invalid.csv", index=False)
    print(f"  {'sample_invalid.csv':<24} {2:>6,} rows")


if __name__ == "__main__":
    main()
