import pytest

from agentsec import __version__
from agentsec.cli import main


def test_alpha_version_and_help(capsys):
    assert __version__ == "0.1.0a0"
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    assert "agentsec 0.1.0a0" in capsys.readouterr().out
