"""파이프라인 단계들이 공유하는 환경 설정.

2단계는 여기 값을 인텐트 인자에 굽고, 3단계는 같은 값을 찾아 관측한다. 둘이
어긋나면 앱이 정상 동작해도 아무것도 관측되지 않으므로, 환경 값은 여기 한 곳에만
두고 2단계 설정은 build_assembly_config() 로 파생시킨다.

환경(어디에 무엇이 떠 있나)과 정책(후보를 몇 개까지, 언제 멈추나)은 바뀌는 주기가
달라 따로 둔다. 한 덩어리면 상한 하나 조정하려다 싱크홀 도메인을 건드리게 된다.
"""

from __future__ import annotations

from dataclasses import dataclass


# 네트워크 봉쇄 방식
NETWORK_OFF = "off"                  # 와이파이·데이터를 끈다. 나갈 경로 자체가 없다
NETWORK_DNS_BLACKHOLE = "dns_blackhole"   # 연결성은 살리고 이름 해석만 죽인다 (미구현)


@dataclass(frozen=True)
class EnvironmentConfig:
    """0·2·3단계가 공유하는 환경. 값이 어긋나면 관측이 통째로 실패한다"""

    # ── 네트워크 ───────────────────────────────────────────────────────
    # 기본은 차단이다. 테스트하려는 싱크가 네트워크를 쓰든 말든, 앱을 띄우는 것만으로
    # 애널리틱스·크래시 리포터·광고 SDK 가 제3자 서버로 통신한다. 우리는 일부러 이상한
    # 값을 넣어 크래시를 유발하므로 그 리포트가 남의 대시보드를 오염시키고, 주입한
    # 마커가 남의 프로덕션 로그에 남을 수도 있다.
    #
    # 대가는 연결성을 확인하고 빠지는 앱에서 거짓 음성이 난다는 것이다. 그 경우
    # NETWORK_DNS_BLACKHOLE 로 바꾸면 되지만 특권 포트에 DNS 서버가 필요하다.
    network_mode: str = NETWORK_OFF

    # ── 공유 표면: 2단계가 값에 굽는 것 = 3단계가 찾는 것 ──────────────
    canary_dir: str = "/sdcard"         # {canary_dir}/canary_{marker}
    canary_authority: str = "canary"    # content://{marker}.canary/{marker}
    telecom_prefix: str = "1555555"     # tel:1555555{digits}

    # 싱크홀 모드를 켤 때만 쓴다. 기본 경로에서는 쓰이지 않는다.
    host_suffix: str = "sink.test"
    sinkhole_port: int = 8443

    # ── 기기 식별 ──────────────────────────────────────────────────────
    adb_serial: str | None = None       # None 이면 연결된 기기가 하나라고 본다
    snapshot_name: str = "baseline"

    def to_dict(self):
        """직렬화를 위해 dict 로 변환한다"""
        return {
            "network_mode": self.network_mode,
            "host_suffix": self.host_suffix,
            "sinkhole_port": self.sinkhole_port,
            "canary_dir": self.canary_dir,
            "canary_authority": self.canary_authority,
            "telecom_prefix": self.telecom_prefix,
            "adb_serial": self.adb_serial,
            "snapshot_name": self.snapshot_name,
        }

    @staticmethod
    def from_dict(raw):
        """dict(raw) 에서 EnvironmentConfig 를 복원한다"""
        return EnvironmentConfig(**{
            name: raw[name] for name in (
                "network_mode", "host_suffix", "sinkhole_port", "canary_dir",
                "canary_authority", "telecom_prefix", "adb_serial", "snapshot_name",
            ) if name in raw
        })


@dataclass(frozen=True)
class ExecutionConfig:
    """3단계 실행 정책"""

    stop_on_success: bool = True    # 경로 하나가 도달하면 그 경로의 남은 후보를 건너뛴다
    poll_interval_ms: int = 200     # 오라클 채널 확인 간격
    am_timeout_ms: int = 10000      # am 명령 자체의 응답 대기 상한
    grant_permissions: bool = True  # 진입점 권한을 pm grant 로 미리 부여할지
    max_total_cases: int = 0        # 실행 전체의 케이스 상한. 0 이면 무제한
    capture_evidence: bool = False  # 케이스별 원 증거(logcat/채널)를 파일로 남길지


@dataclass(frozen=True)
class AssemblyConfig:
    """2단계 동작을 조절하는 설정"""

    # 2단계 고유 정책
    max_values_per_input: int = 8
    max_cases_per_candidate: int = 32

    # 환경에서 파생되는 값. 직접 채우지 말고 build_assembly_config() 를 쓴다.
    # 3단계가 관측할 대상과 어긋나면 앱이 정상 동작해도 아무것도 안 잡힌다.
    host_suffix: str = "sink.test"
    canary_dir: str = "/sdcard"
    canary_authority: str = "canary"
    telecom_prefix: str = "1555555"


def build_assembly_config(env, **policy):
    """환경 설정(env)에서 2단계 설정을 파생시켜 두 단계가 같은 값을 보게 한다"""
    # 환경 값의 출처는 env 하나뿐이다. policy 로는 상한 같은 2단계 고유 항목만 덮어쓴다.
    forbidden = {"host_suffix", "canary_dir", "canary_authority", "telecom_prefix"}
    overlap = forbidden & set(policy)
    if overlap:
        raise ValueError(
            f"환경 값은 EnvironmentConfig 에서만 정한다. policy 로 덮어쓸 수 없음: {sorted(overlap)}"
        )

    return AssemblyConfig(
        host_suffix=env.host_suffix,
        canary_dir=env.canary_dir,
        canary_authority=env.canary_authority,
        telecom_prefix=env.telecom_prefix,
        **policy,
    )
