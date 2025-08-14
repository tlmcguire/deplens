import logging

from mock import Mock

from twisted.internet import defer

from synapse.rest import admin
from synapse.rest.client.v1 import login, room

from tests.replication._base import BaseMultiWorkerStreamTestCase

logger = logging.getLogger(__name__)


class PusherShardTestCase(BaseMultiWorkerStreamTestCase):
    """Checks pusher sharding works
    """

    servlets = [
        admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor, clock, hs):
        self.other_user_id = self.register_user("otheruser", "pass")
        self.other_access_token = self.login("otheruser", "pass")

    def default_config(self):
        conf = super().default_config()
        conf["start_pushers"] = False
        return conf

    def _create_pusher_and_send_msg(self, localpart):
        user_id = self.register_user(localpart, "pass")
        access_token = self.login(localpart, "pass")

        user_dict = self.get_success(
            self.hs.get_datastore().get_user_by_access_token(access_token)
        )
        token_id = user_dict.token_id

        self.get_success(
            self.hs.get_pusherpool().add_pusher(
                user_id=user_id,
                access_token=token_id,
                kind="http",
                app_id="m.http",
                app_display_name="HTTP Push Notifications",
                device_display_name="pushy push",
                pushkey="a@example.com",
                lang=None,
                data={"url": "https://push.example.com/push"},
            )
        )

        self.pump()

        room = self.helper.create_room_as(user_id, tok=access_token)

        self.helper.join(
            room=room, user=self.other_user_id, tok=self.other_access_token
        )

        response = self.helper.send(room, body="Hi!", tok=self.other_access_token)
        event_id = response["event_id"]

        return event_id

    def test_send_push_single_worker(self):
        """Test that registration works when using a pusher worker.
        """
        http_client_mock = Mock(spec_set=["post_json_get_json"])
        http_client_mock.post_json_get_json.side_effect = lambda *_, **__: defer.succeed(
            {}
        )

        self.make_worker_hs(
            "synapse.app.pusher",
            {"start_pushers": True},
            proxied_blacklisted_http_client=http_client_mock,
        )

        event_id = self._create_pusher_and_send_msg("user")

        self.pump()

        http_client_mock.post_json_get_json.assert_called_once()
        self.assertEqual(
            http_client_mock.post_json_get_json.call_args[0][0],
            "https://push.example.com/push",
        )
        self.assertEqual(
            event_id,
            http_client_mock.post_json_get_json.call_args[0][1]["notification"][
                "event_id"
            ],
        )

    def test_send_push_multiple_workers(self):
        """Test that registration works when using sharded pusher workers.
        """
        http_client_mock1 = Mock(spec_set=["post_json_get_json"])
        http_client_mock1.post_json_get_json.side_effect = lambda *_, **__: defer.succeed(
            {}
        )

        self.make_worker_hs(
            "synapse.app.pusher",
            {
                "start_pushers": True,
                "worker_name": "pusher1",
                "pusher_instances": ["pusher1", "pusher2"],
            },
            proxied_blacklisted_http_client=http_client_mock1,
        )

        http_client_mock2 = Mock(spec_set=["post_json_get_json"])
        http_client_mock2.post_json_get_json.side_effect = lambda *_, **__: defer.succeed(
            {}
        )

        self.make_worker_hs(
            "synapse.app.pusher",
            {
                "start_pushers": True,
                "worker_name": "pusher2",
                "pusher_instances": ["pusher1", "pusher2"],
            },
            proxied_blacklisted_http_client=http_client_mock2,
        )

        event_id = self._create_pusher_and_send_msg("user2")

        self.pump()

        http_client_mock1.post_json_get_json.assert_called_once()
        http_client_mock2.post_json_get_json.assert_not_called()
        self.assertEqual(
            http_client_mock1.post_json_get_json.call_args[0][0],
            "https://push.example.com/push",
        )
        self.assertEqual(
            event_id,
            http_client_mock1.post_json_get_json.call_args[0][1]["notification"][
                "event_id"
            ],
        )

        http_client_mock1.post_json_get_json.reset_mock()
        http_client_mock2.post_json_get_json.reset_mock()

        event_id = self._create_pusher_and_send_msg("user4")

        self.pump()

        http_client_mock1.post_json_get_json.assert_not_called()
        http_client_mock2.post_json_get_json.assert_called_once()
        self.assertEqual(
            http_client_mock2.post_json_get_json.call_args[0][0],
            "https://push.example.com/push",
        )
        self.assertEqual(
            event_id,
            http_client_mock2.post_json_get_json.call_args[0][1]["notification"][
                "event_id"
            ],
        )
