import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError

from app.domain.scans import Scan, ScanAlreadyActiveError, ScanStatus
from app.domain.scoring import DEFAULT_POLICY, score
from app.domain.targets import RegisteredTarget
from app.domain.user import User
from app.infra.models import FindingModel, ScanModel, TargetModel, UserModel
from app.infra.scan_repository import SqlAlchemyScanRepository
from app.infra.target_repository import SqlAlchemyTargetRepository
from app.infra.user_repository import SqlAlchemyUserRepository
from tests.domain.test_scans import FINDING

NOW = datetime.now(UTC)


@pytest.fixture
def repository(db_session):
    return SqlAlchemyScanRepository(db_session)


@pytest.fixture
def target(db_session):
    user = User.create("remy@example.test", "hash")
    SqlAlchemyUserRepository(db_session).add(user)
    target = RegisteredTarget.create(user.id, "example.com").mark_verified(NOW)
    SqlAlchemyTargetRepository(db_session).add(target)
    return target


@pytest.fixture
def pending(repository, target):
    scan = Scan.create(target.id)
    repository.add(scan)
    return scan


def test_add_get_and_active_round_trip(repository, pending, db_session):
    db_session.expire_all()
    assert repository.get(pending.id) == pending
    assert repository.get_active_for_target(pending.target_id) == pending
    assert repository.get(uuid.uuid4()) is None
    assert repository.get_active_for_target(uuid.uuid4()) is None


@pytest.mark.parametrize("running", [False, True])
def test_partial_index_rejects_second_active_and_preserves_session(repository, pending, running):
    if running:
        repository.save(pending.start(NOW))
    with pytest.raises(ScanAlreadyActiveError):
        repository.add(Scan.create(pending.target_id))
    assert repository.get(pending.id) is not None


@pytest.mark.parametrize("terminal", [ScanStatus.DONE, ScanStatus.FAILED])
def test_terminal_scan_allows_new_pending(repository, pending, terminal):
    ended = (
        pending.start(NOW).complete(score([FINDING], DEFAULT_POLICY), NOW)
        if terminal == ScanStatus.DONE
        else pending.fail("reason", NOW)
    )
    repository.save(ended)
    assert repository.get(pending.id) == ended
    assert repository.get_active_for_target(pending.target_id) is None
    fresh = Scan.create(pending.target_id)
    repository.add(fresh)
    assert repository.get_active_for_target(pending.target_id) == fresh


def test_two_targets_allow_two_active_scans(repository, pending, target, db_session):
    other = RegisteredTarget.create(target.user_id, "other.example.com")
    SqlAlchemyTargetRepository(db_session).add(other)
    fresh = Scan.create(other.id)
    repository.add(fresh)
    assert repository.get_active_for_target(other.id) == fresh
    assert repository.get_active_for_target(target.id) == pending


def test_save_also_translates_partial_index_violation(repository, pending):
    ended = pending.fail("reason", NOW)
    repository.save(ended)
    fresh = Scan.create(pending.target_id)
    repository.add(fresh)
    with pytest.raises(ScanAlreadyActiveError):
        repository.save(pending.start(NOW))
    assert repository.get(pending.id) == ended
    assert repository.get(fresh.id) == fresh


def test_other_integrity_errors_are_not_translated(repository):
    with pytest.raises(IntegrityError, match="fk_scans_target_id_targets"):
        repository.add(Scan.create(uuid.uuid4()))
    assert repository.get(uuid.uuid4()) is None


def test_findings_keep_duplicate_rule_ids_and_are_replaced(repository, pending):
    repository.replace_findings(pending.id, [FINDING, FINDING])
    assert repository.get_findings(pending.id) == [FINDING, FINDING]
    repository.replace_findings(pending.id, [FINDING])
    assert repository.get_findings(pending.id) == [FINDING]
    repository.replace_findings(pending.id, [])
    assert repository.get_findings(pending.id) == []


@pytest.mark.parametrize("parent", [UserModel, TargetModel, ScanModel])
def test_cascades_remove_scans_and_findings(repository, target, pending, db_session, parent):
    repository.replace_findings(pending.id, [FINDING])
    identifier = {UserModel: target.user_id, TargetModel: target.id, ScanModel: pending.id}[parent]
    db_session.execute(delete(parent).where(parent.id == identifier))
    db_session.expire_all()
    assert repository.get(pending.id) is None
    assert repository.get_findings(pending.id) == []
    assert db_session.scalars(select(FindingModel)).all() == []


def test_scan_defaults_are_filled(target, db_session):
    model = ScanModel(target_id=target.id, status="pending")
    db_session.add(model)
    db_session.flush()
    db_session.refresh(model)
    assert isinstance(model.id, uuid.UUID)
    assert model.created_at.tzinfo is not None
    assert model.attempts == 0


def test_repository_mutations_never_commit(repository, target, db_session):
    scan = Scan.create(target.id)
    repository.add(scan)
    repository.save(scan.start(NOW))
    repository.replace_findings(scan.id, [FINDING])
    db_session.rollback()
    assert repository.get(scan.id) is None
    assert repository.get_findings(scan.id) == []


def test_list_for_target_since_filters_by_target_and_date(repository, pending, target, db_session):
    old = replace(Scan.create(pending.target_id), created_at=NOW - timedelta(hours=2))
    repository.save(pending.fail("reason", NOW))
    repository.add(old)
    other = RegisteredTarget.create(target.user_id, "other.example.com")
    SqlAlchemyTargetRepository(db_session).add(other)
    repository.add(Scan.create(other.id))
    since = NOW - timedelta(hours=1)
    assert [scan.id for scan in repository.list_for_target_since(pending.target_id, since)] == [
        pending.id
    ]


def test_list_for_target_returns_twenty_latest_with_stable_order(repository, target, db_session):
    other = RegisteredTarget.create(target.user_id, "other.example.com")
    SqlAlchemyTargetRepository(db_session).add(other)
    repository.add(Scan.create(other.id))
    scans = [
        replace(Scan.create(target.id), created_at=NOW + timedelta(seconds=index // 2)).fail(
            "reason", NOW + timedelta(minutes=1)
        )
        for index in range(25)
    ]
    for scan in reversed(scans):
        repository.add(scan)
    expected = sorted(scans, key=lambda scan: (scan.created_at, scan.id), reverse=True)[:20]
    assert repository.list_for_target(target.id) == expected
    assert repository.list_for_target(uuid.uuid4()) == []
