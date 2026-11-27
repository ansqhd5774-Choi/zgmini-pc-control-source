# ZGMINI Controller 공개 소스·격리 CI

기존 보조 Controller의 고정 소스와 Windows 격리시험을 공개 검증하는 저장소입니다.

- 운영 PC·Runner·독립 유지보수기 제어 기능은 등록하지 않습니다.
- CI는 표준 GitHub-hosted Windows에서 실행하며 운영 PC에 접속하지 않습니다.
- 운영 비밀정보, 원자료, 운영 원장, 결과 Artifact는 포함하지 않습니다.
- `SOURCE_REVISION.json`은 원본 저장소 commit과 공개한 파일별 SHA-256을 기록합니다.
- 이 저장소의 CI PASS는 운영 전환·작업 인계 성공을 의미하지 않습니다.
- 운영 코드의 승인·설치 정본은 기존 `zgmini-pc-control`이며 공개 snapshot을 자동 설치하지 않습니다.

기존 프로그램의 기능·산식·원자료·운영 설정은 변경하지 않습니다.
