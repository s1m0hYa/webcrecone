from .cli import main

# python -m webrecon의 진입점. 실제 로직은 테스트에서 직접 호출 가능한 cli.main에 둔다.
raise SystemExit(main())
