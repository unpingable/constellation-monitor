#!/usr/bin/env python3
"""Source fixture for fixed NQ operation controls; never invokes systemd-run."""
import pathlib
import shlex
import subprocess
import unittest

WRAPPER = pathlib.Path(__file__).with_name('nq-ops-as-nq')


def arguments(source):
    return shlex.split(source.replace('\\\n', ''), comments=True)


def controls(argv):
    result = {}
    for argument in argv:
        if argument.startswith('--property='):
            key, value = argument[len('--property='):].split('=', 1)
            if key in result:
                raise ValueError('duplicate control: ' + key)
            result[key] = value
    return result


class NqOpsWrapperTests(unittest.TestCase):
    def test_shell_syntax_and_exact_nq_actor_command_forwarding(self):
        subprocess.run(['/bin/sh', '-n', str(WRAPPER)], check=True)
        source = WRAPPER.read_text()
        self.assertIn('-- /usr/bin/nq "$@"', source)
        argv = arguments(source)
        self.assertEqual(argv[:2], ['exec', '/usr/bin/systemd-run'])
        self.assertEqual(argv[-3:], ['--', '/usr/bin/nq', '$@'])
        self.assertTrue({'--quiet', '--wait', '--pipe', '--collect'} <= set(argv))
        properties = controls(argv)
        self.assertEqual(properties['User'], 'nq')
        self.assertEqual(properties['Group'], 'nq')
        self.assertEqual(properties['ReadWritePaths'], '/var/lib/nq-ops /run/nq-ops')
        self.assertEqual(properties['CapabilityBoundingSet'], 'CAP_SETUID CAP_SETGID CAP_CHOWN CAP_KILL')
        self.assertEqual(properties['AmbientCapabilities'], properties['CapabilityBoundingSet'])

    def assert_envelope(self, properties):
        self.assertEqual({key: properties.get(key) for key in ('LimitFSIZE', 'MemoryMax', 'MemorySwapMax')},
                         {'LimitFSIZE': '1G', 'MemoryMax': '2G', 'MemorySwapMax': '0'})

    def test_fixed_package_file_and_memory_envelope(self):
        self.assert_envelope(controls(arguments(WRAPPER.read_text())))

    def test_missing_or_different_limit_is_detected(self):
        original = controls(arguments(WRAPPER.read_text()))
        for key in ('LimitFSIZE', 'MemoryMax', 'MemorySwapMax'):
            with self.subTest(key=key):
                missing = dict(original)
                del missing[key]
                with self.assertRaises(AssertionError):
                    self.assert_envelope(missing)
                changed = dict(original, **{key: 'unlimited'})
                with self.assertRaises(AssertionError):
                    self.assert_envelope(changed)


if __name__ == '__main__':
    unittest.main()
