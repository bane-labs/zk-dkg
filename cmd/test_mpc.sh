# phase1 common srs
date "+%Y-%m-%d %H:%M:%S"
go run mpccmd.go phase1 init --output Phase1_1
date "+%Y-%m-%d %H:%M:%S"
go run mpccmd.go phase1 contribute --phase1file Phase1_1 --output Phase1_2
date "+%Y-%m-%d %H:%M:%S"
go run mpccmd.go phase1 verify --phase1file Phase1_1 --output Phase1_2
date "+%Y-%m-%d %H:%M:%S"
go run mpccmd.go phase1 seal --phase1file Phase1_2 --output srs_1
date "+%Y-%m-%d %H:%M:%S"

# for each batch_encryption_circuit(batch=1,2,7), run phase2
go run mpccmd.go phase2 init --srsfile srs_1 --output Phase2_Batch_1_1 --batch 1
date "+%Y-%m-%d %H:%M:%S"
go run mpccmd.go phase2 contribute --phase2file Phase2_Batch_1_1 --output Phase2_Batch_1_2
date "+%Y-%m-%d %H:%M:%S"
go run mpccmd.go phase2 verify --phase2file Phase2_Batch_1_1 --output Phase2_Batch_1_2
date "+%Y-%m-%d %H:%M:%S"
go run mpccmd.go seal --batch 1 --srsfile srs_1 --phase2file Phase2_Batch_1_2 --contract batch_encryption_1.sol --provingkey batch_encryption_1.pk --verifyingkey batch_encryption_1.vk --r1cs batch_encryption_1.ccs
date "+%Y-%m-%d %H:%M:%S"

go run mpccmd.go phase2 init --srsfile srs_1 --output Phase2_Batch_2_1 --batch 2
date "+%Y-%m-%d %H:%M:%S"
go run mpccmd.go phase2 contribute --phase2file Phase2_Batch_2_1 --output Phase2_Batch_2_2
date "+%Y-%m-%d %H:%M:%S"
go run mpccmd.go phase2 verify --phase2file Phase2_Batch_2_1 --output Phase2_Batch_2_2
date "+%Y-%m-%d %H:%M:%S"
go run mpccmd.go seal --batch 2 --srsfile srs_1 --phase2file Phase2_Batch_2_2 --contract batch_encryption_2.sol --provingkey batch_encryption_2.pk --verifyingkey batch_encryption_2.vk --r1cs batch_encryption_2.ccs
date "+%Y-%m-%d %H:%M:%S"

go run mpccmd.go phase2 init --srsfile srs_1 --output Phase2_Batch_7_1 --batch 7
date "+%Y-%m-%d %H:%M:%S"
go run mpccmd.go phase2 contribute --phase2file Phase2_Batch_7_1 --output Phase2_Batch_7_2
date "+%Y-%m-%d %H:%M:%S"
go run mpccmd.go phase2 verify --phase2file Phase2_Batch_7_1 --output Phase2_Batch_7_2
date "+%Y-%m-%d %H:%M:%S"
go run mpccmd.go seal --batch 7 --srsfile srs_1 --phase2file Phase2_Batch_7_2 --contract batch_encryption_7.sol --provingkey batch_encryption_7.pk --verifyingkey batch_encryption_7.vk --r1cs batch_encryption_7.ccs
date "+%Y-%m-%d %H:%M:%S"