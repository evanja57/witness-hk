# -*- encoding: utf-8 -*-
"""
tests.witopnet.app.test_indirecting module

Tests for witness event intake and key-state endpoints.
"""

from datetime import timedelta
from unittest.mock import MagicMock

import falcon
import pyotp
import pytest
from falcon import testing
from hio.base import doing
from keri import core, kering
from keri.app import forwarding, habbing
from keri.app.httping import CESR_DESTINATION_HEADER
from keri.help import helping
from keri.peer import exchanging

from witopnet.app.indirecting import HttpEnd, KeyLogEnd, KeyStateEnd
from witopnet.core import basing, witnessing


@pytest.fixture
def http_witery():
    db = basing.Baser(name="http-put", temp=True)
    witery = witnessing.Witnessery(db=db, temp=True)
    doist = doing.Doist(doers=[witery])
    try:
        doist.enter()
        app = falcon.App()
        app.add_route("/", HttpEnd(witery=witery))
        yield witery, testing.TestClient(app)
    finally:
        doist.exit()
        db.close(clear=True)


@pytest.mark.parametrize(
    "kind", (kering.Kinds.json, kering.Kinds.cbor, kering.Kinds.mgpk)
)
def test_http_put_forwards_stream_to_selected_mailbox(http_witery, monkeypatch, kind):
    witery, client = http_witery
    with (
        habbing.openHab(name="sender", version=kering.Vrsn_2_0) as (hby, sender),
        habbing.openHab(name="recipient", version=kering.Vrsn_2_0) as (rhby, recipient),
    ):
        witness = witery.createWitness(recipient.pre)
        other = witery.createWitness(sender.pre)
        monkeypatch.setattr(
            sender,
            "endsFor",
            lambda pre: {kering.Roles.witness: {witness.hab.pre: {"http": witery.url}}},
        )
        poster = forwarding.StreamPoster(
            hby=hby, hab=sender, recp=recipient.pre, topic="echo", kind=kind
        )
        messages = []
        for text in ("first", "second"):
            exn = core.exchange(
                sender=sender.pre,
                route="/echo",
                attributes={"msg": text},
                version=kering.Vrsn_2_0,
                kind=kind,
            )
            msg = sender.endorse(exn, last=False, framed=False, gvrsn=kering.Vrsn_2_0)
            poster.send(serder=exn, attachment=msg[exn.size :])
            messages.append(exn)

        (messenger,) = poster.deliver()
        try:
            (request,) = messenger.client.requests
            assert request["method"] == "PUT"
            headers = {key: str(value) for key, value in request["headers"].items()}
            body = bytes(request["body"])
            topic = f"{recipient.pre}/echo"
            response = client.simulate_put("/", body=body)
            assert response.status_code == 400
            response = client.simulate_put(
                "/", body=body, headers={CESR_DESTINATION_HEADER: recipient.pre}
            )
            assert response.status_code == 404
            assert not list(witness.mbx.cloneTopicIter(topic=topic))

            for malformed in (b'{"v":', b"-"):
                response = client.simulate_put("/", body=malformed, headers=headers)
                assert response.status_code == 204
                assert not list(witness.mbx.cloneTopicIter(topic=topic))

            # An unsigned message must not block the complete frames that follow it.
            invalid = core.exchange(
                sender=sender.pre,
                route="/fwd",
                modifiers={"pre": recipient.pre, "topic": "echo"},
                attributes={"evt": messages[0].said},
                version=kering.Vrsn_2_0,
                kind=kind,
            )
            witness.parser.version = kering.Vrsn_1_0
            headers["Content-Length"] = str(len(invalid.raw) + len(body))
            response = client.simulate_put(
                "/", body=invalid.raw + body, headers=headers
            )
            assert response.status_code == 204
            assert witness.parser.version == kering.Vrsn_2_0
            assert sender.pre in witness.hab.kevers
            assert witness.hby.db.exns.get((invalid.said,)) is None
            rows = list(witness.mbx.cloneTopicIter(topic=topic))
            assert len(rows) == 2
            assert not list(other.mbx.cloneTopicIter(topic=topic))
            assert sender.pre not in other.hab.kevers

            exc = exchanging.Exchanger(hby=rhby, handlers=[])
            parser = core.Parser(kvy=rhby.kvy, exc=exc, version=kering.Vrsn_2_0)
            parser.parse(ims=sender.replay(gvrsn=kering.Vrsn_2_0), local=False)
            for exn, (_, _, stored) in zip(messages, rows, strict=True):
                parser.parse(ims=bytearray(stored), local=False)
                assert exc.complete(exn.said)
                assert exchanging.verify(rhby, exn)
                assert rhby.db.exns.get((exn.said,)).raw == exn.raw
        finally:
            messenger.client.close()


@pytest.mark.parametrize("version", (kering.Vrsn_1_0, kering.Vrsn_2_0))
def test_http_put_requires_valid_auth_for_locally_witnessed_events(
    http_witery, version
):
    witery, client = http_witery
    with habbing.openHab(
        name="controller", version=version, kind=kering.Kinds.json
    ) as (_, controller):
        witness = witery.createWitness(controller.pre)
        headers = {CESR_DESTINATION_HEADER: witness.hab.pre}
        response = client.simulate_put(
            "/", body=controller.msgOwnInception(gvrsn=kering.Vrsn_2_0), headers=headers
        )
        assert response.status_code == 204
        assert witness.hab.kevers[controller.pre].sn == 0

        rotation = controller.rotate(
            adds=[witness.hab.pre], version=version, gvrsn=kering.Vrsn_2_0
        )
        response = client.simulate_put("/", body=rotation, headers=headers)
        assert response.status_code == 204
        assert witness.hab.kevers[controller.pre].sn == 0

        secret = b"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
        encrypter = core.Encrypter(verkey=witness.hab.kever.verfers[0].qb64b)
        seed = core.Matter(raw=secret, code=core.MtrDex.Ed25519_Seed)
        witness.addCode(encrypter.encrypt(ser=seed.qb64b))
        now = helping.nowUTC()
        totp = pyotp.TOTP(secret)
        valid = totp.at(now)
        wrong = str((int(valid) + 1) % 1000000).zfill(6)
        expired = now - timedelta(minutes=11)
        for auth in (
            None,
            f"{wrong}#{now.isoformat()}",
            "invalid",
            f"{valid}#invalid",
            f"{valid}#{now.replace(tzinfo=None).isoformat()}",
            f"{totp.at(expired)}#{expired.isoformat()}",
        ):
            request_headers = dict(headers)
            if auth is not None:
                request_headers["Authorization"] = auth
            response = client.simulate_put("/", body=rotation, headers=request_headers)
            assert response.status_code == 204
            assert witness.hab.kevers[controller.pre].sn == 0
            assert controller.kever.serder.said in witness.hab.db.misfits.get(
                (controller.pre, controller.kever.serder.snh)
            )

        response = client.simulate_put(
            "/",
            body=rotation,
            headers={**headers, "Authorization": f"{valid}#{now.isoformat()}"},
        )
        assert response.status_code == 204
        assert witness.hab.kevers[controller.pre].sn == 1
        assert witness.hab.kevers[controller.pre].serder.pvrsn == version

        interaction = controller.interact(gvrsn=kering.Vrsn_2_0)
        response = client.simulate_put("/", body=interaction, headers=headers)
        assert response.status_code == 204
        assert witness.hab.kevers[controller.pre].sn == 1


class TestKeyStateEnd:
    """Test suite for KeyStateEnd endpoint"""

    def setup_method(self):
        """Setup test fixtures for each test method"""
        # Create mock witery
        self.witery = MagicMock()

        # Create mock witness
        self.witness = MagicMock()
        self.witness_aid = "EBabiu0K7vLr6FRy8cZl_l5z7hMzOaV85ePSkVWRW9KI"

        # Create mock hab (habitat)
        self.witness.hab = MagicMock()
        self.witness.hab.pre = self.witness_aid

        # Create mock kever (key event receiver)
        self.test_pre = "ENsqL5zLYNbZf0kcOlx-ioqNWlatD9rKZZM4hbEI7nza"
        self.kever = MagicMock()
        self.kever.serder = MagicMock()
        self.kever.serder.saidb = b"test_said"
        self.kever.toader = MagicMock()
        self.kever.toader.num = 2

        # Mock kever state
        self.kever_state = MagicMock()
        self.kever_state._asdict = MagicMock(
            return_value={
                "i": self.test_pre,
                "s": "1",
                "d": "ETestSAID",
                "et": "ixn",
                "k": ["DTestKey"],
                "n": "ETestNext",
                "wits": ["EWit1", "EWit2"],
                "c": [],
                "ee": {"s": "0", "d": "EPrev"},
                "di": "",
            }
        )
        self.kever.state = MagicMock(return_value=self.kever_state)

        # Setup kevers dictionary
        self.witness.hab.kevers = {self.test_pre: self.kever}

        # Setup database mock
        self.witness.hab.db = MagicMock()
        self.witness.hab.db.wigs = MagicMock()

        # Create mock wigs (witness signatures)
        # Using valid CESR indexed signature format (0B prefix + 88 base64 chars)
        self.mock_wigs = [
            b"0BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAg",
            b"0BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAh",
        ]
        self.witness.hab.db.wigs.get = MagicMock(return_value=self.mock_wigs)

        # Mock endorse method
        self.witness.hab.endorse = MagicMock(return_value=b"endorsed_data")

        # Setup witery lookup to return our witness
        self.witery.lookup = MagicMock(return_value=self.witness)

        # Create endpoint
        self.endpoint = KeyStateEnd(witery=self.witery)

        # Create Falcon app and test client
        self.app = falcon.App()
        self.app.add_route("/ksn", self.endpoint)
        self.client = testing.TestClient(self.app)

    def test_on_get_success(self):
        """Test successful key state query and emitted reply shape."""
        headers = {CESR_DESTINATION_HEADER: self.witness_aid}

        response = self.client.simulate_get(
            "/ksn", query_string=f"pre={self.test_pre}", headers=headers
        )

        assert response.status == falcon.HTTP_200
        assert response.headers["Content-Type"] == "application/cesr"
        assert response.content == b"endorsed_data"

        # Verify witery.lookup was called with correct AID
        self.witery.lookup.assert_called_once_with(self.witness_aid)

        # Verify kever.state was called
        self.kever.state.assert_called_once()

        # Verify endorse was called with a fixed v2 CESR reply serder.
        self.witness.hab.endorse.assert_called_once()
        reply_serder = self.witness.hab.endorse.call_args.args[0]
        assert reply_serder.ked["t"] == "rpy"
        assert kering.deversify(reply_serder.ked["v"]).pvrsn == kering.Vrsn_2_0
        assert reply_serder.kind == kering.Kinds.cesr

    def test_on_get_missing_destination_header(self):
        """Test request without CESR destination header"""
        response = self.client.simulate_get("/ksn", query_string=f"pre={self.test_pre}")

        assert response.status == falcon.HTTP_400
        assert response.json["title"] == "CESR request destination header missing"

    def test_on_get_unknown_aid(self):
        """Test request with unknown AID"""
        unknown_aid = "EUnknownAID123"
        self.witery.lookup = MagicMock(return_value=None)

        headers = {CESR_DESTINATION_HEADER: unknown_aid}
        response = self.client.simulate_get(
            "/ksn", query_string=f"pre={self.test_pre}", headers=headers
        )

        assert response.status == falcon.HTTP_400
        assert "not recognized" in response.json["description"]

    def test_on_get_pre_not_found(self):
        """Test query for non-existent prefix"""
        unknown_pre = "EUnknownPrefix"
        self.witness.hab.kevers = {}  # Empty kevers

        headers = {CESR_DESTINATION_HEADER: self.witness_aid}
        response = self.client.simulate_get(
            "/ksn", query_string=f"pre={unknown_pre}", headers=headers
        )

        assert response.status == falcon.HTTP_404
        assert response.json["title"] == "AID not found"
        assert "not found" in response.json["description"]

    def test_on_get_insufficient_witness_receipts(self):
        """Test when witness receipts are insufficient"""
        # Mock wigs.get to return fewer signatures than required
        self.witness.hab.db.wigs.get = MagicMock(
            return_value=[b"sig1"]
        )  # Only 1, need 2

        headers = {CESR_DESTINATION_HEADER: self.witness_aid}

        response = self.client.simulate_get(
            "/ksn", query_string=f"pre={self.test_pre}", headers=headers
        )

        assert response.status == falcon.HTTP_404
        assert "Witness receipts not found" in response.json["title"]

    def test_on_get_no_witness_receipts(self):
        """Test when there are no witness receipts at all"""
        self.witness.hab.db.wigs.get = MagicMock(return_value=[])

        headers = {CESR_DESTINATION_HEADER: self.witness_aid}
        response = self.client.simulate_get(
            "/ksn", query_string=f"pre={self.test_pre}", headers=headers
        )

        assert response.status == falcon.HTTP_404
        assert "Witness receipts not found" in response.json["title"]


class TestKeyLogEnd:
    """Test suite for KeyLogEnd endpoint"""

    def setup_method(self):
        """Setup test fixtures for each test method"""
        # Create mock witery
        self.witery = MagicMock()

        # Create mock witness
        self.witness = MagicMock()
        self.witness_aid = "EBabiu0K7vLr6FRy8cZl_l5z7hMzOaV85ePSkVWRW9KI"

        # Create mock hab (habitat)
        self.witness.hab = MagicMock()
        self.witness.hab.pre = self.witness_aid

        # Create mock kever
        self.test_pre = "ENsqL5zLYNbZf0kcOlx-ioqNWlatD9rKZZM4hbEI7nza"
        self.kever = MagicMock()
        self.kever.delpre = None  # No delegator
        self.kever.serder = MagicMock()
        self.kever.sner = MagicMock()
        self.kever.sner.num = 5  # Current sequence number

        # Setup kevers dictionary
        self.witness.hab.kevers = {self.test_pre: self.kever}

        # Setup database mock
        self.witness.hab.db = MagicMock()

        # Mock clonePreIter to return key event log messages
        self.mock_msgs = [b"msg1", b"msg2", b"msg3"]
        self.witness.hab.db.clonePreIter = MagicMock(return_value=iter(self.mock_msgs))

        # Mock fullyWitnessed
        self.witness.hab.db.fullyWitnessed = MagicMock(return_value=True)

        # Mock fetchAllSealingEventByEventSeal for anchor tests
        self.witness.hab.db.fetchAllSealingEventByEventSeal = MagicMock(
            return_value=[b"seal"]
        )

        # Setup witery lookup
        self.witery.lookup = MagicMock(return_value=self.witness)

        # Create endpoint
        self.endpoint = KeyLogEnd(witery=self.witery)

        # Create Falcon app and test client
        self.app = falcon.App()
        self.app.add_route("/log", self.endpoint)
        self.client = testing.TestClient(self.app)

    def test_on_get_success_basic(self):
        """Test successful key log query with basic parameters"""
        headers = {CESR_DESTINATION_HEADER: self.witness_aid}

        response = self.client.simulate_get(
            "/log", query_string=f"pre={self.test_pre}", headers=headers
        )

        assert response.status == falcon.HTTP_200
        assert response.headers["Content-Type"] == "application/cesr"

        # Verify the response contains the concatenated messages
        expected_data = b"".join(self.mock_msgs)
        assert response.content == expected_data

        # Verify witery.lookup was called
        self.witery.lookup.assert_called_once_with(self.witness_aid)

        # Verify clonePreIter was called with default fn=0
        self.witness.hab.db.clonePreIter.assert_called_with(pre=self.test_pre, fn=0)

    def test_on_get_with_fn_parameter(self):
        """Test key log query with fn (first seen number) parameter"""
        headers = {CESR_DESTINATION_HEADER: self.witness_aid}
        fn_hex = "a"  # 10 in decimal

        response = self.client.simulate_get(
            "/log", query_string=f"pre={self.test_pre}&fn={fn_hex}", headers=headers
        )

        assert response.status == falcon.HTTP_200

        # Verify clonePreIter was called with correct fn value
        self.witness.hab.db.clonePreIter.assert_called_with(pre=self.test_pre, fn=10)

    def test_on_get_with_sequence_number(self):
        """Test key log query with sequence number parameter"""
        headers = {CESR_DESTINATION_HEADER: self.witness_aid}
        sn_hex = "3"  # 3 in decimal

        response = self.client.simulate_get(
            "/log", query_string=f"pre={self.test_pre}&s={sn_hex}", headers=headers
        )

        assert response.status == falcon.HTTP_200

        # Verify fullyWitnessed was called
        self.witness.hab.db.fullyWitnessed.assert_called_once()

    def test_on_get_with_anchor(self):
        """Test key log query with anchor parameter"""
        headers = {CESR_DESTINATION_HEADER: self.witness_aid}
        anchor = "EAnchorSAID"

        response = self.client.simulate_get(
            "/log", query_string=f"pre={self.test_pre}&a={anchor}", headers=headers
        )

        assert response.status == falcon.HTTP_200

        # Verify fetchAllSealingEventByEventSeal was called
        self.witness.hab.db.fetchAllSealingEventByEventSeal.assert_called_once_with(
            pre=self.test_pre, seal=anchor
        )

    def test_on_get_with_delegator(self):
        """Test key log query when AID has a delegator"""
        # Setup delegator
        del_pre = "EDelegatorPrefix"
        self.kever.delpre = del_pre

        # Mock delegator messages
        del_msgs = [b"del_msg1", b"del_msg2"]

        # Configure clonePreIter to return different iterators for different calls
        def clone_pre_iter_side_effect(pre, fn):
            if pre == self.test_pre:
                return iter(self.mock_msgs)
            elif pre == del_pre:
                return iter(del_msgs)
            return iter([])

        self.witness.hab.db.clonePreIter = MagicMock(
            side_effect=clone_pre_iter_side_effect
        )

        headers = {CESR_DESTINATION_HEADER: self.witness_aid}
        response = self.client.simulate_get(
            "/log", query_string=f"pre={self.test_pre}", headers=headers
        )

        assert response.status == falcon.HTTP_200

        # Verify both regular and delegator messages are included
        expected_data = b"".join(self.mock_msgs) + b"".join(del_msgs)
        assert response.content == expected_data

    def test_on_get_missing_destination_header(self):
        """Test request without CESR destination header"""
        response = self.client.simulate_get("/log", query_string=f"pre={self.test_pre}")

        assert response.status == falcon.HTTP_400
        assert response.json["title"] == "CESR request destination header missing"

    def test_on_get_unknown_aid(self):
        """Test request with unknown AID"""
        unknown_aid = "EUnknownAID456"
        self.witery.lookup = MagicMock(return_value=None)

        headers = {CESR_DESTINATION_HEADER: unknown_aid}
        response = self.client.simulate_get(
            "/log", query_string=f"pre={self.test_pre}", headers=headers
        )

        assert response.status == falcon.HTTP_400
        assert "not recognized" in response.json["description"]

    def test_on_get_pre_not_found(self):
        """Test query for non-existent prefix"""
        unknown_pre = "EUnknownPrefix789"
        self.witness.hab.kevers = {}  # Empty kevers

        headers = {CESR_DESTINATION_HEADER: self.witness_aid}
        response = self.client.simulate_get(
            "/log", query_string=f"pre={unknown_pre}", headers=headers
        )

        assert response.status == falcon.HTTP_404
        assert response.json["title"] == "AID not found"
        assert "not found" in response.json["description"]

    def test_on_get_anchor_not_found(self):
        """Test query with anchor that doesn't exist"""
        # Mock fetchAllSealingEventByEventSeal to return empty list
        self.witness.hab.db.fetchAllSealingEventByEventSeal = MagicMock(return_value=[])

        headers = {CESR_DESTINATION_HEADER: self.witness_aid}
        anchor = "EMissingAnchor"

        response = self.client.simulate_get(
            "/log", query_string=f"pre={self.test_pre}&a={anchor}", headers=headers
        )

        assert response.status == falcon.HTTP_404
        assert "not found" in response.json["description"]

    def test_on_get_sequence_number_too_high(self):
        """Test query with sequence number higher than current"""
        # Set current sn to 5, but query for sn=10
        self.kever.sner.num = 5

        headers = {CESR_DESTINATION_HEADER: self.witness_aid}
        sn_hex = "a"  # 10 in decimal

        response = self.client.simulate_get(
            "/log", query_string=f"pre={self.test_pre}&s={sn_hex}", headers=headers
        )

        assert response.status == falcon.HTTP_404
        assert "not found" in response.json["description"]

    def test_on_get_not_fully_witnessed(self):
        """Test query when event is not fully witnessed"""
        self.witness.hab.db.fullyWitnessed = MagicMock(return_value=False)

        headers = {CESR_DESTINATION_HEADER: self.witness_aid}
        sn_hex = "2"

        response = self.client.simulate_get(
            "/log", query_string=f"pre={self.test_pre}&s={sn_hex}", headers=headers
        )

        assert response.status == falcon.HTTP_404
        assert "not found" in response.json["description"]

    def test_on_get_no_events_found(self):
        """Test query when no events are found"""
        # Mock clonePreIter to return empty iterator
        self.witness.hab.db.clonePreIter = MagicMock(return_value=iter([]))

        headers = {CESR_DESTINATION_HEADER: self.witness_aid}
        response = self.client.simulate_get(
            "/log", query_string=f"pre={self.test_pre}", headers=headers
        )

        assert response.status == falcon.HTTP_404
        assert "No events found" in response.json["description"]

    def test_on_get_hex_parsing(self):
        """Test that hex parameters are correctly parsed"""
        headers = {CESR_DESTINATION_HEADER: self.witness_aid}

        # Test with hexadecimal values that won't trigger 404
        # Use sn within range (current is 5)
        sn_hex = "2"  # 2 in decimal
        fn_hex = "10"  # 16 in decimal

        response = self.client.simulate_get(
            "/log",
            query_string=f"pre={self.test_pre}&s={sn_hex}&fn={fn_hex}",
            headers=headers,
        )

        assert response.status == falcon.HTTP_200
        # Verify clonePreIter was called with correct decimal fn value
        self.witness.hab.db.clonePreIter.assert_called_with(pre=self.test_pre, fn=16)
