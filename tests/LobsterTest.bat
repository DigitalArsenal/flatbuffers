..\Release\flatc.exe --lobster -I include_test monster_test.fbs
..\Release\flatc.exe --lobster -I include_test optional_scalars.fbs
..\..\lobster\bin\lobster.exe .\lobstertest.lobster
..\Release\flatc.exe --lobster -I encryption_v3 -o encryption_v3 encryption_v3\node.fbs
..\..\lobster\bin\lobster.exe .\lobster_encryption_test.lobster
