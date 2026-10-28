from pydantic import SecretStr

from leash.judge import MuseWonderJudge, build_judge
from leash.secrets import SecretScanner
from leash.settings import Settings


def test_secret_values_are_not_exposed_in_repr() -> None:
    settings = Settings(
        model_api_key=SecretStr("meta-super-secret"),
    )

    rendered = repr(settings)

    assert "meta-super-secret" not in rendered
    assert settings.model_api_key_configured is True


def test_managed_judge_uses_muse_wonder_with_model_api_key() -> None:
    settings = Settings(
        leash_judge_mode="managed",
        model_api_key=SecretStr("meta-super-secret"),
    )

    judge = build_judge(settings, SecretScanner("test-redaction-key"))

    assert isinstance(judge, MuseWonderJudge)
