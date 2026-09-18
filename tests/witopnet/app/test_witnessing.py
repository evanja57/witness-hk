# -*- encoding: utf-8 -*-
"""
tests.app.test_witnessing module

"""

import errno
import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import falcon
from falcon import testing
from hio.base import doing
from keri import kering
from keri.app import habbing
from keri.core import eventing, parsing
from keri.help import helping

from witopnet.core import basing, oobing, witnessing

CONTROLLER_AID = "ENsqL5zLYNbZf0kcOlx-ioqNWlatD9rKZZM4hbEI7nza"


def _stream_messages(stream):
    """Parse every KERI message and its CESR attachments from an OOBI stream."""
    ims = bytearray(stream)
    results = parsing.Parser().parse(ims=ims, framed=False, processive=False)
    assert not ims
    return results


def test_delete_witness_removes_registry_before_closing():
    witery = witnessing.Witnessery.__new__(witnessing.Witnessery)
    witery.wits = {}
    witery.db = SimpleNamespace(wits=MagicMock(), cids=MagicMock())
    witery.remove = MagicMock()

    witness = MagicMock()
    witness.aids = ["AID_1"]
    witness.hby = MagicMock()
    witery.wits["EID_1"] = witness

    witery.deleteWitness("EID_1")

    assert "EID_1" not in witery.wits
    witery.db.wits.rem.assert_called_once_with(keys=("EID_1",))
    witery.db.cids.rem.assert_called_once_with(keys=("AID_1",), val="EID_1")
    witery.remove.assert_called_once_with([witness])
    witness.hby.close.assert_called_once_with(clear=True)


def test_fd_exhaustion_detection_handles_oserror_and_lmdb_text():
    assert witnessing._isFdExhaustion(OSError(errno.EMFILE, "Too many open files"))
    assert witnessing._isFdExhaustion(RuntimeError("lmdb failure: Too many open files"))


def test_create_witness_fd_exhaustion_returns_service_unavailable():
    witery = MagicMock()
    witery.createWitness.side_effect = RuntimeError("lmdb failure: Too many open files")

    endpoint = witnessing.WitnessCollectionEnd(witery=witery)
    app = falcon.App()
    app.add_route("/witnesses", endpoint)
    client = testing.TestClient(app)

    response = client.simulate_post("/witnesses", json={"aid": CONTROLLER_AID})

    assert response.status == falcon.HTTP_503
    assert response.json["title"] == "Witness service unavailable"
    witery._logFdExhaustion.assert_called_once_with(CONTROLLER_AID)


def test_setup_keeps_config_dir_out_of_witopnet_db_path():
    with (
        patch.object(witnessing.basing, "Baser") as mock_baser,
        patch.object(witnessing.configing, "Configer") as mock_configer,
        patch.object(witnessing, "BaserDoer", return_value=MagicMock(name="db-doer")),
        patch.object(witnessing, "Witnessery", return_value=MagicMock(name="witery")),
        patch.object(
            witnessing, "createHttpServer", return_value=MagicMock(name="server")
        ),
        patch.object(
            witnessing.http, "ServerDoer", return_value=MagicMock(name="server-doer")
        ),
        patch.object(
            witnessing.oobing, "OOBIEnd", return_value=MagicMock(name="oobi-end")
        ),
        patch.object(witnessing, "HttpEnd", return_value=MagicMock(name="http-end")),
        patch.object(
            witnessing, "ReceiptEnd", return_value=MagicMock(name="receipt-end")
        ),
        patch.object(witnessing, "KeyStateEnd", return_value=MagicMock(name="ksn-end")),
        patch.object(witnessing, "KeyLogEnd", return_value=MagicMock(name="klog-end")),
        patch.object(witnessing.aiding, "loadEnds"),
    ):
        mock_baser.return_value = SimpleNamespace(name="witopnet")

        witnessing.setup(base="witopnet", temp=False, headDirPath="/tmp/config-root")

    mock_baser.assert_called_once_with(name="witopnet", base="witopnet", temp=False)
    mock_configer.assert_called_once_with(
        name="witopnet", headDirPath="/tmp/config-root", temp=False
    )


def test_oobi_closed_witness_db_returns_not_found():
    aid = "EAID123"
    witness = SimpleNamespace(
        hby=SimpleNamespace(
            kevers={aid: SimpleNamespace(serder=MagicMock())},
            db=SimpleNamespace(opened=False),
            prefixes=set(),
            habs={},
        )
    )
    witery = MagicMock()
    witery.lookup.return_value = witness

    endpoint = oobing.OOBIEnd(witery=witery)
    app = falcon.App()
    app.add_route("/oobi/{aid}/{role}", endpoint)
    client = testing.TestClient(app)

    response = client.simulate_get(f"/oobi/{aid}/controller")

    assert response.status == falcon.HTTP_404


def test_self_owned_oobi_reuses_stored_reply_record_versions():
    """Self-owned OOBIs should keep the authored version of stored reply records."""

    with habbing.openHab(
        name="wan-oobi",
        transferable=False,
        salt=b"0123456789fedoob",
        version=kering.Vrsn_2_0,
        kind=eventing.Kinds.json,
    ) as (_, wanHab):
        url = "http://127.0.0.1:5642/"
        msgs = bytearray()

        # Set up the witness and its OOBI endpoint
        msgs.extend(
            wanHab.makeEndRole(
                eid=wanHab.pre,
                role=kering.Roles.controller,
                stamp=helping.nowIso8601(),
                version=kering.Vrsn_2_0,
            )
        )
        msgs.extend(
            wanHab.makeLocScheme(
                url=url,
                scheme=kering.Schemes.http,
                stamp=helping.nowIso8601(),
                version=kering.Vrsn_2_0,
            )
        )

        # Parse the records
        wanHab.psr.parse(ims=msgs)

        # Set up the doist and witery
        doist = doing.Doist(limit=1.0, tock=0.03125, real=True)
        safe = basing.Baser(name=wanHab.name, temp=wanHab.temp)
        witery = witnessing.Witnessery(db=safe, temp=wanHab.temp)
        deeds = doist.enter(doers=[witery])
        doist.recur(deeds=deeds)

        endpoint = oobing.OOBIEnd(witery=witery)
        app = falcon.App()
        app.add_route("/witnesses", witnessing.WitnessCollectionEnd(witery))
        app.add_route("/oobi/{aid}", endpoint)
        app.add_route("/oobi/{aid}/{role}", endpoint)
        client = testing.TestClient(app)

        # Provision a witness identifier for wanHab
        rep_w = client.simulate_post(
            path="/witnesses", body=json.dumps({"aid": wanHab.pre})
        )
        assert rep_w.status == falcon.HTTP_OK
        witness_aid = rep_w.json["eid"]
        witness = witery.wits[witness_aid]

        # Fetch the OOBI and assert it is successful and parse the messages
        with (
            patch.object(
                witness.hab,
                "replyToOobi",
                wraps=witness.hab.replyToOobi,
            ) as reply_to_oobi,
        ):
            response = client.simulate_get(f"/oobi/{witness_aid}")

        assert response.status_code == 200
        assert response.content_type == "application/json+cesr"
        assert reply_to_oobi.call_args.kwargs["pvrsn"] == kering.Vrsn_2_0
        assert reply_to_oobi.call_args.kwargs["gvrsn"] == kering.Vrsn_2_0
        assert reply_to_oobi.call_args.kwargs["kind"] == eventing.Kinds.json
        messages = _stream_messages(response.content)

        # Stored reply bodies keep the version in which they were authored while
        # replyToOobi applies the requested genus to their attachments. This
        # witness's endpoint metadata and requested genus are both v2.
        replies = [result.serder for result in messages if result.serder.ilk == "rpy"]
        assert replies
        assert all(serder.pvrsn == kering.Vrsn_2_0 for serder in replies)
        assert all(serder.kind == eventing.Kinds.json for serder in replies)

        self_events = [
            result
            for result in messages
            if result.serder.pre == witness_aid
            and result.serder.ilk
            in (
                eventing.Ilks.icp,
                eventing.Ilks.rot,
                eventing.Ilks.ixn,
                eventing.Ilks.dip,
                eventing.Ilks.drt,
            )
        ]
        assert self_events
        assert all(result.serder.pvrsn == kering.Vrsn_2_0 for result in self_events)
        assert all(result.sigers for result in self_events)
        assert all(result.frcs for result in self_events)

        # Fetch the OOBI again and confirm the stored reply versions remain
        # stable across repeated requests.
        response = client.simulate_get(f"/oobi/{witness_aid}")
        assert response.status_code == 200
        messages = _stream_messages(response.content)

        # The stored reply records keep their original authored v2 format
        # across repeated OOBI fetches too.
        replies = [result.serder for result in messages if result.serder.ilk == "rpy"]
        assert replies
        assert all(serder.pvrsn == kering.Vrsn_2_0 for serder in replies)
        assert all(serder.kind == eventing.Kinds.json for serder in replies)


def test_witnessed_controller_oobi_uses_serving_habitat_genus():
    with (
        habbing.openHab(
            name="wan-oobi-seed",
            transferable=False,
            salt=b"0123456789feowit",
            version=kering.Vrsn_2_0,
            kind=eventing.Kinds.json,
        ) as (_, seedHab),
        habbing.openHab(
            name="bob-oobi-controller",
            salt=b"0123456789feoctl",
            version=kering.Vrsn_1_0,
            kind=eventing.Kinds.json,
        ) as (_, bobHab),
    ):
        safe = basing.Baser(name=seedHab.name, temp=seedHab.temp)
        witery = witnessing.Witnessery(db=safe, temp=seedHab.temp)
        witness = witery.createWitness(aid=bobHab.pre)

        witness.parser.parseOne(
            ims=bytearray(bobHab.msgOwnInception(gvrsn=kering.Vrsn_1_0)),
            local=False,
            version=kering.Vrsn_1_0,
        )
        rotation = bobHab.rotate(
            adds=[witness.hab.pre],
            version=kering.Vrsn_1_0,
            gvrsn=kering.Vrsn_1_0,
        )
        witness.parser.parseOne(
            ims=bytearray(rotation),
            local=True,
            version=kering.Vrsn_1_0,
        )
        assert bobHab.pre in witness.hab.kevers
        assert witness.hab.pre in witness.hab.kevers[bobHab.pre].wits

        endpoint = oobing.OOBIEnd(witery=witery)
        app = falcon.App()
        app.add_route("/oobi/{aid}", endpoint)
        client = testing.TestClient(app)

        with (
            patch.object(witness.hab.db, "fullyWitnessed", return_value=True),
            patch.object(
                witness.hab,
                "replyToOobi",
                wraps=witness.hab.replyToOobi,
            ) as reply_to_oobi,
        ):
            response = client.simulate_get(f"/oobi/{bobHab.pre}")

        assert response.status_code == 200
        assert response.content_type == "application/json+cesr"
        assert reply_to_oobi.call_args.kwargs["pvrsn"] == kering.Vrsn_2_0
        assert reply_to_oobi.call_args.kwargs["gvrsn"] == kering.Vrsn_2_0
        assert reply_to_oobi.call_args.kwargs["kind"] == eventing.Kinds.json

        messages = _stream_messages(response.content)
        controller_events = [
            result for result in messages if result.serder.pre == bobHab.pre
        ]
        assert controller_events
        assert all(
            result.serder.pvrsn == kering.Vrsn_1_0 for result in controller_events
        )
        assert all(result.sigers for result in controller_events)
        assert all(result.frcs for result in controller_events)


def test_delete_missing_witness_returns_not_found():
    witery = MagicMock()
    witery.deleteWitness.side_effect = ValueError("missing witness")

    endpoint = witnessing.WitnessResourceEnd(witery=witery)
    app = falcon.App()
    app.add_route("/witnesses/{eid}", endpoint)
    client = testing.TestClient(app)

    response = client.simulate_delete(
        "/witnesses/BHMXjwXav5p1j1tvD6cgIPoLE7ke3us0YUmTMPKLjmgi"
    )

    assert response.status == falcon.HTTP_404
