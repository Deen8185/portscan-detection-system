"""Phase 0 checks: the environment and the central settings are in place."""

from portscan import config


def test_libraries_import():
    import joblib, matplotlib, pandas, plotly, sklearn, streamlit  # noqa: F401


def test_feature_list_matches_table_3_1():
    assert len(config.FEATURES) == 16
    assert len(set(config.FEATURES)) == 16


def test_destination_port_is_not_a_model_feature():
    assert config.DESTINATION_PORT_COLUMN not in config.FEATURES
    assert config.DESTINATION_PORT_COLUMN in config.REQUIRED_UPLOAD_COLUMNS


def test_split_settings_follow_the_design():
    assert config.TEST_SIZE == 0.20
    assert config.RF_N_ESTIMATORS == 100
    assert config.KNN_K == 5


def test_project_folders_exist():
    for folder in (config.RAW_DIR, config.PROCESSED_DIR, config.SAMPLES_DIR,
                   config.MODELS_DIR, config.FIGURES_DIR, config.TABLES_DIR):
        assert folder.is_dir(), folder
