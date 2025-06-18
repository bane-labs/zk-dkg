go run mpccmd.go export innerCircuit
go run mpccmd.go CommonSRS init --inner-ccs inner_ccs_7 --srs srs_1
go run mpccmd.go CommonSRS checkInit --inner-ccs inner_ccs_7 --srs srs_1
go run mpccmd.go CommonSRS contribute --inner-ccs inner_ccs_7 --input srs_1 --output srs_2
go run mpccmd.go CommonSRS verify --inner-ccs inner_ccs_7 --input srs_1 --output srs_2
go run mpccmd.go export innerSeal --srs srs_2 --inner-ccs inner_ccs_ --inner-pk inner_pk_ --inner-vk inner_vk_
go run mpccmd.go export outerSeal --srs srs_2 --inner-ccs inner_ccs_ --inner-pk inner_pk_ --inner-vk inner_vk_