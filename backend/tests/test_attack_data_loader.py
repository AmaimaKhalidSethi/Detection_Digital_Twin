from app.mitre.attack_data_loader import all_techniques, get_technique


def test_loader_returns_technique_metadata_with_description():
    technique = get_technique("T1059.001")

    assert technique is not None
    assert technique["name"]
    assert technique["tactic"]
    assert "description" in technique
    assert isinstance(technique["description"], str)
    assert len(technique["description"]) <= 500


def test_all_techniques_returns_attck_ids():
    techniques = all_techniques()

    assert "T1059.001" in techniques
    assert techniques["T1059.001"]["name"]
    assert techniques["T1059.001"]["tactic"]


def test_tactic_is_normalized_to_title_case_and_uses_first_phase():
    technique = get_technique("T1059.001")
    techniques = all_techniques()

    assert technique is not None
    assert technique["tactic"] == "Execution"
    assert techniques["T1053.005"]["tactic"] == "Execution"
