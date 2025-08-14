
from synapse.api.room_versions import RoomVersions
from synapse.events import FrozenEvent
from synapse.push import push_rule_evaluator
from synapse.push.push_rule_evaluator import PushRuleEvaluatorForEvent

from tests import unittest


class PushRuleEvaluatorTestCase(unittest.TestCase):
    def _get_evaluator(self, content):
        event = FrozenEvent(
            {
                "event_id": "$event_id",
                "type": "m.room.history_visibility",
                "sender": "@user:test",
                "state_key": "",
                "room_id": "#room:test",
                "content": content,
            },
            RoomVersions.V1,
        )
        room_member_count = 0
        sender_power_level = 0
        power_levels = {}
        return PushRuleEvaluatorForEvent(
            event, room_member_count, sender_power_level, power_levels
        )

    def test_display_name(self):
        """Check for a matching display name in the body of the event."""
        evaluator = self._get_evaluator({"body": "foo bar baz"})

        condition = {
            "kind": "contains_display_name",
        }

        self.assertFalse(evaluator.matches(condition, "@user:test", ""))

        self.assertFalse(evaluator.matches(condition, "@user:test", "not found"))

        self.assertTrue(evaluator.matches(condition, "@user:test", "foo"))

        self.assertFalse(evaluator.matches(condition, "@user:test", "ba"))

        self.assertFalse(evaluator.matches(condition, "@user:test", "ba[rz]"))

        self.assertTrue(evaluator.matches(condition, "@user:test", "foo bar"))

    def test_no_body(self):
        """Not having a body shouldn't break the evaluator."""
        evaluator = self._get_evaluator({})

        condition = {
            "kind": "contains_display_name",
        }
        self.assertFalse(evaluator.matches(condition, "@user:test", "foo"))

    def test_invalid_body(self):
        """A non-string body should not break the evaluator."""
        condition = {
            "kind": "contains_display_name",
        }

        for body in (1, True, {"foo": "bar"}):
            evaluator = self._get_evaluator({"body": body})
            self.assertFalse(evaluator.matches(condition, "@user:test", "foo"))

    def test_tweaks_for_actions(self):
        """
        This tests the behaviour of tweaks_for_actions.
        """

        actions = [
            {"set_tweak": "sound", "value": "default"},
            {"set_tweak": "highlight"},
            "notify",
        ]

        self.assertEqual(
            push_rule_evaluator.tweaks_for_actions(actions),
            {"sound": "default", "highlight": True},
        )
