from core.ruleset import RuleConfig
from rules.php.god_class import GodClassRule
from schemas.facts import Facts, ClassInfo, MethodInfo


def test_god_class_does_not_mix_methods_across_same_class_name_different_namespaces():
    facts = Facts(project_path=".")

    # Two classes with the same short name but different namespaces/files.
    facts.classes.append(
        ClassInfo(
            name="UserService",
            fqcn="App\\Services\\UserService",
            file_path="app/Services/UserService.php",
            file_hash="a",
            line_start=1,
            line_end=120,
        )
    )
    facts.classes.append(
        ClassInfo(
            name="UserService",
            fqcn="Domain\\Users\\UserService",
            file_path="domain/Users/UserService.php",
            file_hash="b",
            line_start=1,
            line_end=120,
        )
    )

    # Each class has 2 public methods; if we mixed by class_name only, we'd count 4.
    for i in range(2):
        facts.methods.append(
            MethodInfo(
                name=f"m{i}",
                class_name="UserService",
                class_fqcn="App\\Services\\UserService",
                file_path="app/Services/UserService.php",
                file_hash="a",
                line_start=10 + i * 10,
                line_end=15 + i * 10,
                loc=6,
                visibility="public",
            )
        )
        facts.methods.append(
            MethodInfo(
                name=f"m{i}",
                class_name="UserService",
                class_fqcn="Domain\\Users\\UserService",
                file_path="domain/Users/UserService.php",
                file_hash="b",
                line_start=10 + i * 10,
                line_end=15 + i * 10,
                loc=6,
                visibility="public",
            )
        )

    rule = GodClassRule(RuleConfig(thresholds={"max_methods": 3, "max_loc": 500}))
    res = rule.run(facts, project_type="")

    # Neither class individually exceeds max_methods=3.
    assert not any(f.rule_id == "god-class" for f in res.findings)


def test_god_class_skips_service_coordinator_facade():
    facts = Facts(project_path=".")
    facts.classes.append(
        ClassInfo(
            name="GameServer",
            fqcn="App\\Services\\Game\\GameServer",
            file_path="app/Services/Game/GameServer.php",
            file_hash="server",
            line_start=1,
            line_end=450,
        )
    )
    facts.methods.append(
        MethodInfo(
            name="__construct",
            class_name="GameServer",
            class_fqcn="App\\Services\\Game\\GameServer",
            file_path="app/Services/Game/GameServer.php",
            file_hash="server",
            line_start=23,
            line_end=31,
            loc=9,
            parameters=[
                "GameServerQueueServiceInterface $queue",
                "GameServerRedisCircuitBreaker $redisCircuitBreaker",
                "GameSocketTokenServiceInterface $tokenService",
                "GameSocketCommandServiceInterface $commandService",
                "SessionVisibilityServiceInterface $sessionVisibility",
                "GameServerEventHandler $eventHandler",
                "GameServerConnectionManager $connectionManager",
            ],
        )
    )
    for idx in range(8):
        facts.methods.append(
            MethodInfo(
                name=f"run{idx}",
                class_name="GameServer",
                class_fqcn="App\\Services\\Game\\GameServer",
                file_path="app/Services/Game/GameServer.php",
                file_hash="server",
                line_start=40 + (idx * 20),
                line_end=60 + (idx * 20),
                loc=21,
                visibility="public",
            )
        )

    rule = GodClassRule(RuleConfig(thresholds={"max_methods": 20, "max_loc": 300}))
    res = rule.run(facts, project_type="")
    assert not any(f.rule_id == "god-class" for f in res.findings)


def test_god_class_skips_interface_backed_service_facade_with_many_thin_methods():
    facts = Facts(project_path=".")
    facts.classes.append(
        ClassInfo(
            name="LmsAdminService",
            fqcn="App\\Services\\Lms\\LmsAdminService",
            file_path="app/Services/Lms/LmsAdminService.php",
            file_hash="svc",
            line_start=1,
            line_end=420,
            implements=["App\\Services\\Lms\\Contracts\\LmsAdminServiceInterface"],
        )
    )
    facts.methods.append(
        MethodInfo(
            name="__construct",
            class_name="LmsAdminService",
            class_fqcn="App\\Services\\Lms\\LmsAdminService",
            file_path="app/Services/Lms/LmsAdminService.php",
            file_hash="svc",
            line_start=10,
            line_end=16,
            loc=7,
            parameters=[
                "AdminServiceCoordinator $coordinator",
                "SettingsServiceInterface $settings",
            ],
        )
    )
    for idx in range(24):
        facts.methods.append(
            MethodInfo(
                name=f"method{idx}",
                class_name="LmsAdminService",
                class_fqcn="App\\Services\\Lms\\LmsAdminService",
                file_path="app/Services/Lms/LmsAdminService.php",
                file_hash="svc",
                line_start=30 + (idx * 8),
                line_end=33 + (idx * 8),
                loc=4,
                visibility="public",
                call_sites=["$this->coordinator->users()->createUser($data)"],
            )
        )

    rule = GodClassRule(RuleConfig(thresholds={"max_methods": 20, "max_loc": 300}))
    res = rule.run(facts, project_type="")
    assert not any(f.rule_id == "god-class" for f in res.findings)


def test_god_class_skips_command_dispatch_service_facade():
    facts = Facts(project_path=".")
    facts.classes.append(
        ClassInfo(
            name="LmsGameService",
            fqcn="App\\Services\\Lms\\LmsGameService",
            file_path="app/Services/Lms/LmsGameService.php",
            file_hash="svc2",
            line_start=1,
            line_end=538,
            implements=["App\\Services\\Lms\\Contracts\\LmsGameServiceInterface"],
        )
    )
    facts.methods.append(
        MethodInfo(
            name="__construct",
            class_name="LmsGameService",
            class_fqcn="App\\Services\\Lms\\LmsGameService",
            file_path="app/Services/Lms/LmsGameService.php",
            file_hash="svc2",
            line_start=10,
            line_end=18,
            loc=9,
            parameters=[
                "SessionLifecycleServiceInterface $lifecycle",
                "TurnManagementServiceInterface $turnService",
                "TeamManagementServiceInterface $teamService",
                "BoardManagementServiceInterface $boardService",
                "GameCommandCoordinator $coordinator",
                "GameOperationsServiceInterface $operations",
            ],
        )
    )
    facts.methods.extend(
        [
            MethodInfo(
                name="dispatch",
                class_name="LmsGameService",
                class_fqcn="App\\Services\\Lms\\LmsGameService",
                file_path="app/Services/Lms/LmsGameService.php",
                file_hash="svc2",
                line_start=30,
                line_end=75,
                loc=46,
                visibility="public",
                call_sites=[
                    "$this->assertAdmin($actor);",
                    "$this->startCategory($actor, $payload);",
                    "$this->advanceTurn($payload, $type === 'admin:skip_turn');",
                    "$this->processWrong($payload);",
                ],
            ),
            MethodInfo(
                name="claimGameEnd",
                class_name="LmsGameService",
                class_fqcn="App\\Services\\Lms\\LmsGameService",
                file_path="app/Services/Lms/LmsGameService.php",
                file_hash="svc2",
                line_start=80,
                line_end=92,
                loc=13,
                visibility="public",
                call_sites=["$this->operations->claimGameEnd($sessionId);"],
            ),
            MethodInfo(
                name="applySeriesPointsIfNeeded",
                class_name="LmsGameService",
                class_fqcn="App\\Services\\Lms\\LmsGameService",
                file_path="app/Services/Lms/LmsGameService.php",
                file_hash="svc2",
                line_start=95,
                line_end=102,
                loc=8,
                visibility="public",
                call_sites=["$this->operations->applySeriesPointsIfNeeded($sessionId);"],
            ),
        ]
    )
    for idx, name in enumerate(
        ["startCategory", "advanceTurn", "processWrong", "revealTile", "undoAction", "gameStatus"]
    ):
        facts.methods.append(
            MethodInfo(
                name=name,
                class_name="LmsGameService",
                class_fqcn="App\\Services\\Lms\\LmsGameService",
                file_path="app/Services/Lms/LmsGameService.php",
                file_hash="svc2",
                line_start=120 + idx * 20,
                line_end=130 + idx * 20,
                loc=11,
                visibility="private",
                call_sites=["$this->coordinator->execute($payload);"],
            )
        )

    rule = GodClassRule(RuleConfig(thresholds={"max_methods": 20, "max_loc": 300}))
    res = rule.run(facts, project_type="")
    assert not any(f.rule_id == "god-class" for f in res.findings)
