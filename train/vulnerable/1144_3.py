
import os
import pathlib
import shutil
import subprocess
import tempfile
import typing
import unittest

import pytest

import ops
from ops.model import _ModelBackend
from ops.storage import SQLiteStorage


def fake_script(test_case: unittest.TestCase, name: str, content: str):
    if not hasattr(test_case, 'fake_script_path'):
        fake_script_path = tempfile.mkdtemp('-fake_script')
        old_path = os.environ['PATH']
        os.environ['PATH'] = os.pathsep.join([fake_script_path, os.environ['PATH']])

        def cleanup():
            shutil.rmtree(fake_script_path)
            os.environ['PATH'] = old_path

        test_case.addCleanup(cleanup)
        test_case.fake_script_path = pathlib.Path(fake_script_path)

    template_args: typing.Dict[str, str] = {
        'name': name,
        'path': test_case.fake_script_path.as_posix(),
        'content': content,
    }

    path: pathlib.Path = test_case.fake_script_path / name
    with path.open('wt') as f:
        f.write(
            """#!/bin/sh
{{ printf {name}; printf "\\036%s" "$@"; printf "\\034"; }} >> {path}/calls.txt
{content}""".format_map(template_args)
        )
    os.chmod(str(path), 0o755)
    path.with_suffix('.bat').write_text(
        f'@"C:\\Program Files\\git\\bin\\bash.exe" {path} %*\n'
    )


def fake_script_calls(
    test_case: unittest.TestCase, clear: bool = False
) -> typing.List[typing.List[str]]:
    calls_file: pathlib.Path = test_case.fake_script_path / 'calls.txt'
    if not calls_file.exists():
        return []

    with calls_file.open('r+t', newline='\n', encoding='utf8') as f:
        calls = [line.split('\x1e') for line in f.read().split('\x1c')[:-1]]
        if clear:
            f.truncate(0)
    return calls


def create_framework(
    request: pytest.FixtureRequest, *, meta: typing.Optional[ops.CharmMeta] = None
):
    env_backup = os.environ.copy()
    os.environ['PATH'] = os.pathsep.join([
        str(pathlib.Path(__file__).parent / 'bin'),
        os.environ['PATH'],
    ])
    os.environ['JUJU_UNIT_NAME'] = 'local/0'

    tmpdir = pathlib.Path(tempfile.mkdtemp())

    class CustomEvent(ops.EventBase):
        pass

    class TestCharmEvents(ops.CharmEvents):
        custom = ops.EventSource(CustomEvent)

    ops.CharmBase.on = TestCharmEvents()

    if meta is None:
        meta = ops.CharmMeta()
    model = ops.Model(meta, _ModelBackend('local/0'))
    framework = ops.Framework(SQLiteStorage(':memory:'), tmpdir, meta, model)

    def finalizer():
        os.environ.clear()
        os.environ.update(env_backup)
        shutil.rmtree(tmpdir)
        ops.CharmBase.on = ops.CharmEvents()
        framework.close()

    request.addfinalizer(finalizer)

    return framework


class FakeScript:
    def __init__(
        self,
        request: pytest.FixtureRequest,
        path: typing.Optional[pathlib.Path] = None,
    ):
        if path is None:
            fake_script_path = tempfile.mkdtemp('-fake_script')
            self.path = pathlib.Path(fake_script_path)
            old_path = os.environ['PATH']
            os.environ['PATH'] = os.pathsep.join([fake_script_path, os.environ['PATH']])

            def cleanup():
                shutil.rmtree(self.path)
                os.environ['PATH'] = old_path

            request.addfinalizer(cleanup)
        else:
            self.path = path

    def write(self, name: str, content: str):
        template_args: typing.Dict[str, str] = {
            'name': name,
            'path': self.path.as_posix(),
            'content': content,
        }

        path: pathlib.Path = self.path / name
        with path.open('wt') as f:
            f.write(
                """#!/bin/sh
{{ printf {name}; printf "\\036%s" "$@"; printf "\\034"; }} >> {path}/calls.txt
{content}""".format_map(template_args)
            )
        path.chmod(0o755)
        path.with_suffix('.bat').write_text(
            f'@"C:\\Program Files\\git\\bin\\bash.exe" {path} %*\n'
        )

    def calls(self, clear: bool = False) -> typing.List[typing.List[str]]:
        calls_file: pathlib.Path = self.path / 'calls.txt'
        if not calls_file.exists():
            return []

        with calls_file.open('r+t', newline='\n', encoding='utf8') as f:
            calls = [line.split('\036') for line in f.read().split('\034')[:-1]]
            if clear:
                f.truncate(0)
        return calls


class FakeScriptTest(unittest.TestCase):
    def test_fake_script_works(self):
        fake_script(self, 'foo', 'echo foo runs')
        fake_script(self, 'bar', 'echo bar runs')
        output = subprocess.getoutput('foo a "b c " && bar "d e" f')
        assert output == 'foo runs\nbar runs'
        assert fake_script_calls(self) == [
            ['foo', 'a', 'b c '],
            ['bar', 'd e', 'f'],
        ]

    def test_fake_script_clear(self):
        fake_script(self, 'foo', 'echo foo runs')

        output = subprocess.getoutput('foo a "b c"')
        assert output == 'foo runs'

        assert fake_script_calls(self, clear=True) == [['foo', 'a', 'b c']]

        fake_script(self, 'bar', 'echo bar runs')

        output = subprocess.getoutput('bar "d e" f')
        assert output == 'bar runs'

        assert fake_script_calls(self, clear=True) == [['bar', 'd e', 'f']]

        assert fake_script_calls(self, clear=True) == []
