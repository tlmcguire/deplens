from mock import Mock

from twisted.internet.defer import Deferred

import synapse.rest.admin
from synapse.logging.context import make_deferred_yieldable
from synapse.rest.client.v1 import login, room
from synapse.rest.client.v2_alpha import receipts

from tests.unittest import HomeserverTestCase, override_config


class HTTPPusherTests(HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        login.register_servlets,
        receipts.register_servlets,
    ]
    user_id = True
    hijack_auth = False

    def make_homeserver(self, reactor, clock):
        self.push_attempts = []

        m = Mock()

        def post_json_get_json(url, body):
            d = Deferred()
            self.push_attempts.append((d, url, body))
            return make_deferred_yieldable(d)

        m.post_json_get_json = post_json_get_json

        config = self.default_config()
        config["start_pushers"] = True

        hs = self.setup_test_homeserver(config=config, proxied_http_client=m)

        return hs

    def test_sends_http(self):
        """
        The HTTP pusher will send pushes for each message to a HTTP endpoint
        when configured to do so.
        """
        user_id = self.register_user("user", "pass")
        access_token = self.login("user", "pass")

        other_user_id = self.register_user("otheruser", "pass")
        other_access_token = self.login("otheruser", "pass")

        user_tuple = self.get_success(
            self.hs.get_datastore().get_user_by_access_token(access_token)
        )
        token_id = user_tuple.token_id

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
                data={"url": "example.com"},
            )
        )

        room = self.helper.create_room_as(user_id, tok=access_token)

        self.helper.join(room=room, user=other_user_id, tok=other_access_token)

        self.helper.send(room, body="Hi!", tok=other_access_token)
        self.helper.send(room, body="There!", tok=other_access_token)

        pushers = self.get_success(
            self.hs.get_datastore().get_pushers_by({"user_name": user_id})
        )
        pushers = list(pushers)
        self.assertEqual(len(pushers), 1)
        last_stream_ordering = pushers[0]["last_stream_ordering"]

        self.pump()

        pushers = self.get_success(
            self.hs.get_datastore().get_pushers_by({"user_name": user_id})
        )
        pushers = list(pushers)
        self.assertEqual(len(pushers), 1)
        self.assertEqual(last_stream_ordering, pushers[0]["last_stream_ordering"])

        self.assertEqual(len(self.push_attempts), 1)
        self.assertEqual(self.push_attempts[0][1], "example.com")
        self.assertEqual(
            self.push_attempts[0][2]["notification"]["content"]["body"], "Hi!"
        )

        self.push_attempts[0][0].callback({})
        self.pump()

        pushers = self.get_success(
            self.hs.get_datastore().get_pushers_by({"user_name": user_id})
        )
        pushers = list(pushers)
        self.assertEqual(len(pushers), 1)
        self.assertTrue(pushers[0]["last_stream_ordering"] > last_stream_ordering)
        last_stream_ordering = pushers[0]["last_stream_ordering"]

        self.assertEqual(len(self.push_attempts), 2)
        self.assertEqual(self.push_attempts[1][1], "example.com")
        self.assertEqual(
            self.push_attempts[1][2]["notification"]["content"]["body"], "There!"
        )

        self.push_attempts[1][0].callback({})
        self.pump()

        pushers = self.get_success(
            self.hs.get_datastore().get_pushers_by({"user_name": user_id})
        )
        pushers = list(pushers)
        self.assertEqual(len(pushers), 1)
        self.assertTrue(pushers[0]["last_stream_ordering"] > last_stream_ordering)

    def test_sends_high_priority_for_encrypted(self):
        """
        The HTTP pusher will send pushes at high priority if they correspond
        to an encrypted message.
        This will happen both in 1:1 rooms and larger rooms.
        """
        user_id = self.register_user("user", "pass")
        access_token = self.login("user", "pass")

        other_user_id = self.register_user("otheruser", "pass")
        other_access_token = self.login("otheruser", "pass")

        yet_another_user_id = self.register_user("yetanotheruser", "pass")
        yet_another_access_token = self.login("yetanotheruser", "pass")

        room = self.helper.create_room_as(user_id, tok=access_token)

        self.helper.join(room=room, user=other_user_id, tok=other_access_token)

        user_tuple = self.get_success(
            self.hs.get_datastore().get_user_by_access_token(access_token)
        )
        token_id = user_tuple.token_id

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
                data={"url": "example.com"},
            )
        )

        self.helper.send_event(
            room,
            "m.room.encrypted",
            content={
                "algorithm": "m.megolm.v1.aes-sha2",
                "sender_key": "6lImKbzK51MzWLwHh8tUM3UBBSBrLlgup/OOCGTvumM",
                "ciphertext": "AwgAErABoRxwpMipdgiwXgu46rHiWQ0DmRj0qUlPrMraBUDk"
                "leTnJRljpuc7IOhsYbLY3uo2WI0ab/ob41sV+3JEIhODJPqH"
                "TK7cEZaIL+/up9e+dT9VGF5kRTWinzjkeqO8FU5kfdRjm+3w"
                "0sy3o1OCpXXCfO+faPhbV/0HuK4ndx1G+myNfK1Nk/CxfMcT"
                "BT+zDS/Df/QePAHVbrr9uuGB7fW8ogW/ulnydgZPRluusFGv"
                "J3+cg9LoPpZPAmv5Me3ec7NtdlfN0oDZ0gk3TiNkkhsxDG9Y"
                "YcNzl78USI0q8+kOV26Bu5dOBpU4WOuojXZHJlP5lMgdzLLl"
                "EQ0",
                "session_id": "IigqfNWLL+ez/Is+Duwp2s4HuCZhFG9b9CZKTYHtQ4A",
                "device_id": "AHQDUSTAAA",
            },
            tok=other_access_token,
        )

        self.pump()

        self.push_attempts[0][0].callback({})
        self.pump()

        self.assertEqual(len(self.push_attempts), 1)
        self.assertEqual(self.push_attempts[0][1], "example.com")
        self.assertEqual(self.push_attempts[0][2]["notification"]["prio"], "high")

        self.helper.join(
            room=room, user=yet_another_user_id, tok=yet_another_access_token
        )

        self.pump()
        self.assertEqual(len(self.push_attempts), 1)

        self.helper.send_event(
            room,
            "m.room.encrypted",
            content={
                "ciphertext": "AwgAEoABtEuic/2DF6oIpNH+q/PonzlhXOVho8dTv0tzFr5m"
                "9vTo50yabx3nxsRlP2WxSqa8I07YftP+EKWCWJvTkg6o7zXq"
                "6CK+GVvLQOVgK50SfvjHqJXN+z1VEqj+5mkZVN/cAgJzoxcH"
                "zFHkwDPJC8kQs47IHd8EO9KBUK4v6+NQ1uE/BIak4qAf9aS/"
                "kI+f0gjn9IY9K6LXlah82A/iRyrIrxkCkE/n0VfvLhaWFecC"
                "sAWTcMLoF6fh1Jpke95mljbmFSpsSd/eEQw",
                "device_id": "SRCFTWTHXO",
                "session_id": "eMA+bhGczuTz1C5cJR1YbmrnnC6Goni4lbvS5vJ1nG4",
                "algorithm": "m.megolm.v1.aes-sha2",
                "sender_key": "rC/XSIAiYrVGSuaHMop8/pTZbku4sQKBZwRwukgnN1c",
            },
            tok=other_access_token,
        )

        self.pump()
        self.assertEqual(len(self.push_attempts), 2)
        self.assertEqual(self.push_attempts[1][1], "example.com")
        self.assertEqual(self.push_attempts[1][2]["notification"]["prio"], "high")

    def test_sends_high_priority_for_one_to_one_only(self):
        """
        The HTTP pusher will send pushes at high priority if they correspond
        to a message in a one-to-one room.
        """
        user_id = self.register_user("user", "pass")
        access_token = self.login("user", "pass")

        other_user_id = self.register_user("otheruser", "pass")
        other_access_token = self.login("otheruser", "pass")

        yet_another_user_id = self.register_user("yetanotheruser", "pass")
        yet_another_access_token = self.login("yetanotheruser", "pass")

        room = self.helper.create_room_as(user_id, tok=access_token)

        self.helper.join(room=room, user=other_user_id, tok=other_access_token)

        user_tuple = self.get_success(
            self.hs.get_datastore().get_user_by_access_token(access_token)
        )
        token_id = user_tuple.token_id

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
                data={"url": "example.com"},
            )
        )

        self.helper.send(room, body="Hi!", tok=other_access_token)

        self.pump()

        self.push_attempts[0][0].callback({})
        self.pump()

        self.assertEqual(len(self.push_attempts), 1)
        self.assertEqual(self.push_attempts[0][1], "example.com")
        self.assertEqual(self.push_attempts[0][2]["notification"]["prio"], "high")

        self.helper.join(
            room=room, user=yet_another_user_id, tok=yet_another_access_token
        )

        self.pump()
        self.assertEqual(len(self.push_attempts), 1)

        self.helper.send(room, body="Welcome!", tok=other_access_token)

        self.pump()
        self.assertEqual(len(self.push_attempts), 2)
        self.assertEqual(self.push_attempts[1][1], "example.com")

        self.assertEqual(self.push_attempts[1][2]["notification"]["prio"], "low")

    def test_sends_high_priority_for_mention(self):
        """
        The HTTP pusher will send pushes at high priority if they correspond
        to a message containing the user's display name.
        """
        user_id = self.register_user("user", "pass")
        access_token = self.login("user", "pass")

        other_user_id = self.register_user("otheruser", "pass")
        other_access_token = self.login("otheruser", "pass")

        yet_another_user_id = self.register_user("yetanotheruser", "pass")
        yet_another_access_token = self.login("yetanotheruser", "pass")

        room = self.helper.create_room_as(user_id, tok=access_token)

        self.helper.join(room=room, user=other_user_id, tok=other_access_token)
        self.helper.join(
            room=room, user=yet_another_user_id, tok=yet_another_access_token
        )

        user_tuple = self.get_success(
            self.hs.get_datastore().get_user_by_access_token(access_token)
        )
        token_id = user_tuple.token_id

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
                data={"url": "example.com"},
            )
        )

        self.helper.send(room, body="Oh, user, hello!", tok=other_access_token)

        self.pump()

        self.push_attempts[0][0].callback({})
        self.pump()

        self.assertEqual(len(self.push_attempts), 1)
        self.assertEqual(self.push_attempts[0][1], "example.com")
        self.assertEqual(self.push_attempts[0][2]["notification"]["prio"], "high")

        self.helper.send(room, body="Are you there?", tok=other_access_token)

        self.pump()
        self.assertEqual(len(self.push_attempts), 2)
        self.assertEqual(self.push_attempts[1][1], "example.com")

        self.assertEqual(self.push_attempts[1][2]["notification"]["prio"], "low")

    def test_sends_high_priority_for_atroom(self):
        """
        The HTTP pusher will send pushes at high priority if they correspond
        to a message that contains @room.
        """
        user_id = self.register_user("user", "pass")
        access_token = self.login("user", "pass")

        other_user_id = self.register_user("otheruser", "pass")
        other_access_token = self.login("otheruser", "pass")

        yet_another_user_id = self.register_user("yetanotheruser", "pass")
        yet_another_access_token = self.login("yetanotheruser", "pass")

        room = self.helper.create_room_as(other_user_id, tok=other_access_token)

        self.helper.join(room=room, user=user_id, tok=access_token)
        self.helper.join(
            room=room, user=yet_another_user_id, tok=yet_another_access_token
        )

        user_tuple = self.get_success(
            self.hs.get_datastore().get_user_by_access_token(access_token)
        )
        token_id = user_tuple.token_id

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
                data={"url": "example.com"},
            )
        )

        self.helper.send(
            room,
            body="@room eeek! There's a spider on the table!",
            tok=other_access_token,
        )

        self.pump()

        self.push_attempts[0][0].callback({})
        self.pump()

        self.assertEqual(len(self.push_attempts), 1)
        self.assertEqual(self.push_attempts[0][1], "example.com")
        self.assertEqual(self.push_attempts[0][2]["notification"]["prio"], "high")

        self.helper.send(
            room, body="@room the spider is gone", tok=yet_another_access_token
        )

        self.pump()
        self.assertEqual(len(self.push_attempts), 2)
        self.assertEqual(self.push_attempts[1][1], "example.com")

        self.assertEqual(self.push_attempts[1][2]["notification"]["prio"], "low")

    def test_push_unread_count_group_by_room(self):
        """
        The HTTP pusher will group unread count by number of unread rooms.
        """
        self._test_push_unread_count()

        self.assertEqual(
            self.push_attempts[5][2]["notification"]["counts"]["unread"], 1
        )

    @override_config({"push": {"group_unread_count_by_room": False}})
    def test_push_unread_count_message_count(self):
        """
        The HTTP pusher will send the total unread message count.
        """
        self._test_push_unread_count()

        self.assertEqual(
            self.push_attempts[5][2]["notification"]["counts"]["unread"], 4
        )

    def _test_push_unread_count(self):
        """
        Tests that the correct unread count appears in sent push notifications

        Note that:
        * Sending messages will cause push notifications to go out to relevant users
        * Sending a read receipt will cause a "badge update" notification to go out to
          the user that sent the receipt
        """
        user_id = self.register_user("user", "pass")
        access_token = self.login("user", "pass")

        other_user_id = self.register_user("other_user", "pass")
        other_access_token = self.login("other_user", "pass")

        room_id = self.helper.create_room_as(other_user_id, tok=other_access_token)

        self.helper.join(room=room_id, user=user_id, tok=access_token)

        user_tuple = self.get_success(
            self.hs.get_datastore().get_user_by_access_token(access_token)
        )
        token_id = user_tuple.token_id

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
                data={"url": "example.com"},
            )
        )

        response = self.helper.send(
            room_id, body="Hello there!", tok=other_access_token
        )
        first_message_event_id = response["event_id"]

        self.push_attempts[0][0].callback({})
        self.pump()

        self.assertEqual(len(self.push_attempts), 1)
        self.assertEqual(self.push_attempts[0][1], "example.com")

        self.assertEqual(
            self.push_attempts[0][2]["notification"]["counts"]["unread"], 0
        )

        request, channel = self.make_request(
            "POST",
            "/rooms/%s/receipt/m.read/%s" % (room_id, first_message_event_id),
            {},
            access_token=access_token,
        )
        self.assertEqual(channel.code, 200, channel.json_body)

        self.push_attempts[1][0].callback({})
        self.pump()

        self.assertEqual(len(self.push_attempts), 2)
        self.assertEqual(
            self.push_attempts[1][2]["notification"]["counts"]["unread"], 0
        )

        self.helper.send(
            room_id, body="How's the weather today?", tok=other_access_token
        )

        self.push_attempts[2][0].callback({})
        self.pump()

        self.assertEqual(len(self.push_attempts), 3)
        self.assertEqual(
            self.push_attempts[2][2]["notification"]["counts"]["unread"], 1
        )

        self.helper.send(room_id, body="Hello?", tok=other_access_token)

        self.pump()
        self.push_attempts[3][0].callback({})

        self.helper.send(room_id, body="Hello??", tok=other_access_token)

        self.pump()
        self.push_attempts[4][0].callback({})

        self.helper.send(room_id, body="HELLO???", tok=other_access_token)

        self.pump()
        self.push_attempts[5][0].callback({})

        self.assertEqual(len(self.push_attempts), 6)
